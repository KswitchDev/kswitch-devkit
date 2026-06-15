// context.go — execution token propagation via context.Context.
package tokens

import "context"

type contextKeyType struct{}

var contextKey = contextKeyType{}

// WithToken stores the execution token in a context.Context.
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, contextKey, token)
}

// FromContext retrieves the execution token from a context.Context.
// Returns ("", false) if no token is present.
func FromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(contextKey).(string)
	return v, ok && v != ""
}
