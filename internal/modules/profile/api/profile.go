package api

import (
	"context"

	"connectrpc.com/connect"
	profilev1 "github.com/chronos/chronos-go/gen/proto/chronos/profile/v1"
	"github.com/chronos/chronos-go/internal/modules/profile/app"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GetProfile returns the caller's own profile.
func (s *Service) GetProfile(
	ctx context.Context, _ *connect.Request[profilev1.GetProfileRequest],
) (*connect.Response[profilev1.GetProfileResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}

	profile, err := s.queries.Get(ctx, subjectID)
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(toProto(profile)), nil
}

// UpdateProfile applies a sparse change to the caller's own profile.
//
// The pointer-per-field mapping is the whole handler. `GetXxx()` on a proto3
// optional field returns the zero value for an absent field, which would erase
// the distinction this endpoint exists to preserve — so every field is read
// through its `HasXxx()` accessor and passed on as a pointer, unchanged.
func (s *Service) UpdateProfile(
	ctx context.Context, req *connect.Request[profilev1.UpdateProfileRequest],
) (*connect.Response[profilev1.UpdateProfileResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	msg := req.Msg
	cmd := app.UpdateCommand{
		SubjectID:      subjectID,
		IdempotencyKey: key,

		// The generated fields are already *string, because each is declared
		// `optional` in the schema. They are passed through UNTOUCHED rather
		// than read with GetXxx(), and that is the whole handler: GetXxx()
		// returns the zero value for an absent field, which collapses "leave
		// this alone" and "empty this" into one request the app layer could
		// then only guess at.
		//
		// AvatarObjectKey is the one field whose EMPTY value is meaningful: it
		// removes the avatar. Passing the pointer along keeps all three states
		// the wire carried — absent, empty, set.
		DisplayName:     msg.DisplayName,
		Locale:          msg.Locale,
		Timezone:        msg.Timezone,
		AvatarObjectKey: msg.AvatarObjectKey,
	}

	profile, err := s.updates.Update(ctx, cmd)
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&profilev1.UpdateProfileResponse{
		Profile: toProto(profile),
	}), nil
}

// CreateAvatarUpload mints a signed target the browser uploads an image to
// directly.
//
// The response carries the grant and nothing about the caller. No image is read
// here, and none ever will be: this handler's whole job is to hand back a URL
// and the fields that go with it.
func (s *Service) CreateAvatarUpload(
	ctx context.Context, req *connect.Request[profilev1.CreateAvatarUploadRequest],
) (*connect.Response[profilev1.CreateAvatarUploadResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	grant, err := s.avatars.Grant(ctx, app.UploadGrantCommand{
		SubjectID:      subjectID,
		ContentType:    req.Msg.GetContentType(),
		SizeBytes:      req.Msg.GetSizeBytes(),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}

	fields := make([]*profilev1.FormField, 0, len(grant.Fields))
	for _, f := range grant.Fields {
		fields = append(fields, &profilev1.FormField{Key: f.Key, Value: f.Value})
	}
	return connect.NewResponse(&profilev1.CreateAvatarUploadResponse{
		UploadUrl: grant.URL,
		Fields:    fields,
		ObjectKey: grant.ObjectKey,
		ExpiresAt: timestamppb.New(grant.Expires),
		MaxBytes:  grant.MaxBytes,
	}), nil
}

// toProto renders a profile onto the wire.
//
// One function, used by both endpoints that return a profile, so a save and a
// read cannot describe the same state differently.
//
// An absent avatar is an ABSENT message rather than an empty one. A client
// checking `has avatar` gets a true answer; one that read an empty URL out of a
// populated message would render a broken image.
func toProto(p app.Profile) *profilev1.GetProfileResponse {
	out := &profilev1.GetProfileResponse{
		SubjectId:   p.SubjectID,
		DisplayName: p.DisplayName,
		Locale:      p.Locale,
		Timezone:    p.Timezone,
	}
	if !p.UpdatedAt.IsZero() {
		out.UpdatedAt = timestamppb.New(p.UpdatedAt.UTC())
	}
	if !p.Avatar.IsZero() {
		out.Avatar = &profilev1.Avatar{
			Url:          p.Avatar.URL,
			ContentType:  p.Avatar.ContentType,
			SizeBytes:    p.Avatar.SizeBytes,
			UrlExpiresAt: timestamppb.New(p.Avatar.URLExpires.UTC()),
		}
	}
	return out
}
