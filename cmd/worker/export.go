package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/adapter/piivault"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	"github.com/chronos/chronos-go/internal/modules/compliance"
	compliancepg "github.com/chronos/chronos-go/internal/modules/compliance/adapter/postgres"
	complianceapp "github.com/chronos/chronos-go/internal/modules/compliance/app"
	compliancedomain "github.com/chronos/chronos-go/internal/modules/compliance/domain"
	compliancereactor "github.com/chronos/chronos-go/internal/modules/compliance/reactor"
	profiledomain "github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// newExportReactor builds the reactor that turns an accepted request into a run.
//
// # What its absence costs
//
// Every export request is consumed by nothing. The person is told their request
// was accepted, the log agrees, and no workflow ever builds a bundle — so the
// request sits at `pending` forever with no error, no parked event and no
// metric. Article 15 gives a controller one month, and this is the failure that
// runs it out in silence.
func newExportReactor(d *dependencies) (*compliancereactor.Export, error) {
	if d.temporal == nil {
		return nil, errors.New("no Temporal client: building an export is a long-running " +
			"job with a resumable listing, and there is nowhere to run it")
	}
	return compliancereactor.NewExport(
		d.temporal, temporaladapter.ExportWorkflow, d.codec)
}

// newExportActivities builds the I/O half of the export workflow.
func newExportActivities(d *dependencies) (*temporaladapter.ExportActivities, error) {
	switch {
	case d.store == nil:
		return nil, errors.New("no event store: the outcome of a data-subject request is a " +
			"compliance record and it lives in the log")
	case d.piiVault == nil:
		return nil, errors.New("no PII vault: an export IS the personal data the vault " +
			"holds, so there is nothing to export")
	case d.blobs == nil:
		return nil, errors.New("no object store: the bundle is written as an object")
	case d.pool == nil:
		return nil, errors.New("no postgres pool: Article 18 stands in front of Article 15, " +
			"and the restriction is read from a projection")
	}

	restrictions, err := compliancepg.NewRestrictions(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("restriction reader: %w", err)
	}

	// Compliance's OWN codec and registry, built together — the same pattern
	// newIdentityCodec follows and for the same reason: the codec applies the
	// registry on the way in and the repository applies it on the way out, so two
	// registries would let those two disagree about which schema version a stored
	// event is (ADR-029).
	codec, upcasters := newComplianceCodec()

	// The SAME resolver against the SAME schedule the erasure consults (see
	// newErasure), so what a bundle says is retained and what an erasure
	// confirmation says cannot disagree.
	exemptions, err := complianceapp.NewExemptions(complianceapp.ExemptionsDeps{
		Records: complianceapp.AssumeRecordsExist{},
	})
	if err != nil {
		return nil, fmt.Errorf("retention exemptions: %w", err)
	}

	runs, err := complianceapp.NewExportRuns(complianceapp.ExportRunsDeps{
		Exports: eventsourcing.NewRepository[*compliancedomain.Export](
			d.store, codec, upcasters,
			compliancedomain.ExportCategory, compliancedomain.NewExport),
		Profile: exportVaultProfile{vault: d.piiVault},
		Objects: d.blobs,
		// The SAME list the erasure walks. An export that covered less than an
		// erasure deletes would hand somebody an incomplete answer to Article 15
		// and then destroy the part it omitted.
		Prefixes:     complianceapp.SubjectPrefixes(subjectObjectPrefixes),
		Store:        d.blobs,
		Prefix:       profiledomain.AvatarPrefix,
		Restrictions: restrictions,
		Exemptions:   exemptions,
		Now:          clock.System{}.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("export runs: %w", err)
	}
	return temporaladapter.NewExportActivities(exportRunnerAdapter{runs: runs})
}

// exportRunnerAdapter presents the use case as the workflow's port.
//
// Structurally mechanical, and separate for the reason issuerAdapter and
// sweepAdapter are: the adapter package may not import a module, so the
// composition root — the one place allowed to see both — performs the
// conversion.
//
// It also does the one thing neither side can do alone: it maps compliance's
// PermanentExportError onto the workflow engine's own marker, so a subject under
// Article 18 restriction is refused once instead of retried for an hour.
type exportRunnerAdapter struct{ runs *complianceapp.ExportRuns }

var _ temporaladapter.ExportRunner = exportRunnerAdapter{}

func (a exportRunnerAdapter) Begin(
	ctx context.Context, exportID string,
) (temporaladapter.ExportPlanResult, error) {
	plan, err := a.runs.Begin(ctx, exportID)
	if err != nil {
		return temporaladapter.ExportPlanResult{}, permanence(err)
	}
	return temporaladapter.ExportPlanResult{
		SubjectID: plan.SubjectID, Prefixes: plan.Prefixes,
	}, nil
}

func (a exportRunnerAdapter) ListObjects(
	ctx context.Context, prefix, after string,
) (temporaladapter.ExportPageResult, error) {
	page, err := a.runs.ListObjects(ctx, prefix, after)
	if err != nil {
		return temporaladapter.ExportPageResult{}, permanence(err)
	}
	out := temporaladapter.ExportPageResult{
		Cursor:  page.Cursor,
		Objects: make([]temporaladapter.ExportObjectRef, 0, len(page.Objects)),
	}
	for _, o := range page.Objects {
		out.Objects = append(out.Objects, temporaladapter.ExportObjectRef{
			Key: o.Key.String(), Size: o.Size, ModifiedAt: o.ModifiedAt,
		})
	}
	return out, nil
}

func (a exportRunnerAdapter) WriteManifest(
	ctx context.Context, exportID string, objects []temporaladapter.ExportObjectRef,
) (string, error) {
	refs := make([]complianceapp.ExportedObject, 0, len(objects))
	for _, o := range objects {
		refs = append(refs, complianceapp.ExportedObject{
			Key: o.Key, Size: o.Size, ModifiedAt: o.ModifiedAt,
		})
	}
	key, err := a.runs.WriteManifest(ctx, exportID, refs)
	if err != nil {
		return "", permanence(err)
	}
	return key, nil
}

func (a exportRunnerAdapter) Fail(ctx context.Context, exportID, reason string) error {
	return a.runs.Fail(ctx, exportID, reason)
}

// permanence maps a module's permanent failure onto the engine's marker.
//
// The whole reason the distinction survives the process boundary. An activity
// error arrives at the workflow as an ApplicationError that has lost the Go
// type, so the marker has to be attached HERE — where both packages are visible
// — rather than recognised there.
func permanence(err error) error {
	var permanent *complianceapp.PermanentExportError
	if errors.As(err, &permanent) {
		return fmt.Errorf("%w: %s", temporaladapter.ErrPermanentExport, permanent.Permanent())
	}
	return err
}

// exportVaultProfile narrows the vault to the one method an export may call.
//
// It reads EVERY field of a person in one call, which is the most sensitive
// capability in this system. The code holding it should hold nothing else — it
// cannot write, and it cannot erase.
type exportVaultProfile struct{ vault *piivault.Vault }

func (v exportVaultProfile) Profile(
	ctx context.Context, subjectID string,
) (map[string]string, error) {
	profile, err := v.vault.Profile(ctx, pii.SubjectID(subjectID))
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(profile.Fields))
	for field, value := range profile.Fields {
		out[string(field)] = value
	}
	return out, nil
}

// newComplianceCodec pairs a codec with the registry it was built from.
func newComplianceCodec() (*eventcodec.JSON, *eventsourcing.UpcasterRegistry) {
	upcasters := eventsourcing.NewUpcasterRegistry()
	compliance.RegisterSchemas(upcasters)

	codec := eventcodec.NewJSON(upcasters)
	compliance.RegisterEvents(codec)
	return codec, upcasters
}
