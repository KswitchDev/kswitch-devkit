//go:build !otel

// Default no-op OTEL stubs. When built without the "otel" build tag,
// all span operations are silent no-ops. This ensures the SDK compiles
// and works identically without any OTEL dependency.

package kswitch

import "context"

// otelSpan is a no-op span that satisfies the minimal interface used by the interceptor.
type otelSpan struct{}

func (otelSpan) End()                              {}
func (otelSpan) SetAttributes(_ ...any)            {}

// otelStartSpan returns the context unchanged and a no-op span.
func otelStartSpan(ctx context.Context, _ string) (context.Context, otelSpan) {
	return ctx, otelSpan{}
}

// otelSetAllow is a no-op when OTEL is not linked.
func otelSetAllow(_ otelSpan, _, _ string) {}

// otelSetDeny is a no-op when OTEL is not linked.
func otelSetDeny(_ otelSpan, _, _ string) {}
