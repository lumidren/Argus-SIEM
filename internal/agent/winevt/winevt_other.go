//go:build !windows

package winevt

import "context"

func (s *Subscription) run(context.Context, chan<- Event) error { return ErrUnsupported }
