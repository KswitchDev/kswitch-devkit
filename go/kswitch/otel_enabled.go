//go:build otel

// OTEL-enabled span helpers. Built only with `-tags otel` and requires
// go.opentelemetry.io/otel and go.opentelemetry.io/otel/attribute in go.mod.
//
// When the otel build tag is active, CheckAndInvoke emits span attributes
// (kswitch.token_id, kswitch.tool_name, kswitch.governed, kswitch.deny_reason)
// that Layer C (eBPF correlation engine) can join against.

package kswitch

import (
	"context"

	otel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

var enforcementTracer = otel.Tracer("kswitch.enforcement")

// otelStartSpan starts a new OTEL span for enforcement.
func otelStartSpan(ctx context.Context, name string) (context.Context, oteltrace.Span) {
	return enforcementTracer.Start(ctx, name)
}

// otelSetAllow sets span attributes for an ALLOW decision.
func otelSetAllow(span oteltrace.Span, toolName, tokenJTI string) {
	span.SetAttributes(
		attribute.String("kswitch.token_id", tokenJTI),
		attribute.String("kswitch.tool_name", toolName),
		attribute.Bool("kswitch.governed", true),
	)
}

// otelSetDeny sets span attributes for a DENY decision.
func otelSetDeny(span oteltrace.Span, toolName, reason string) {
	span.SetAttributes(
		attribute.String("kswitch.tool_name", toolName),
		attribute.Bool("kswitch.governed", false),
		attribute.String("kswitch.deny_reason", reason),
	)
}
