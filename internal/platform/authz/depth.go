package authz

import "fmt"

// Path is a chain of containers from a root down to a resource, deepest last.
//
// It exists so nesting depth is checked where a hierarchy is BUILT, not where it
// is read. OpenFGA raises a hard error past 25 levels, and a check that errors
// fails closed — so a tree allowed to grow too deep does not produce a warning,
// it produces users locked out of resources they own, with no obvious cause.
type Path []ResourceRef

// Depth is the number of levels, counting the resource itself.
func (p Path) Depth() int { return len(p) }

// Validate rejects a hierarchy that is too deep to be safe.
//
// The cap is MaxDepth (15), not OpenFGA's 25. The gap is deliberate headroom:
// hitting the server's limit is a READ failure and therefore an outage, while
// hitting ours is a rejected WRITE at the moment somebody nests too far — which
// names the problem, points at the resource, and is fixable by the person doing
// it.
func (p Path) Validate() error {
	if len(p) == 0 {
		return fmt.Errorf("%w: an empty path names no resource", ErrInvalid)
	}
	if len(p) > MaxDepth {
		return fmt.Errorf("%w: %s is %d levels deep, over the %d-level limit; "+
			"move it nearer the root", ErrTooDeep, p[len(p)-1], len(p), MaxDepth)
	}
	seen := make(map[ResourceRef]struct{}, len(p))
	for _, r := range p {
		if err := r.valid(); err != nil {
			return err
		}
		// A container that contains itself, directly or transitively, makes
		// depth unbounded — and OpenFGA would then answer by exhausting its
		// traversal limit rather than by returning a decision.
		if _, dup := seen[r]; dup {
			return fmt.Errorf("%w: %s appears twice in the same path, so the hierarchy "+
				"contains a cycle", ErrInvalid, r)
		}
		seen[r] = struct{}{}
	}
	return nil
}

// WouldExceedDepth reports whether attaching a subtree of the given depth under
// parent would breach the cap.
//
// Moving a subtree is where this bites hardest: each individual resource is
// within the limit, and the combined tree is not. Checking only the resource
// being moved would let a re-parent create a tree nothing can read.
func WouldExceedDepth(parent Path, subtreeDepth int) error {
	if subtreeDepth < 1 {
		return fmt.Errorf("%w: a subtree has at least one level", ErrInvalid)
	}
	total := len(parent) + subtreeDepth
	if total > MaxDepth {
		return fmt.Errorf("%w: attaching a %d-level subtree under a %d-level parent gives "+
			"%d levels, over the %d-level limit",
			ErrTooDeep, subtreeDepth, len(parent), total, MaxDepth)
	}
	return nil
}
