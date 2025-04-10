package web

import (
	"context"
	"fmt"
	"net/url"
)

type dynamicCSPContextKeyType struct{}

var dynamicCSPContextKey = dynamicCSPContextKeyType{}

func WithCSPNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, dynamicCSPContextKey, nonce)
}

func GetCSPNonce(ctx context.Context) string {
	nonce, _ := ctx.Value(dynamicCSPContextKey).(string)
	return nonce
}

func CSPDirectives(publicOrigin string, nonce string, cdnHost string, allowInlineScript bool) ([]string, error) {
	u, err := url.Parse(publicOrigin)
	if err != nil {
		return nil, err
	}

	selfSrc := "'self'"
	if cdnHost != "" {
		selfSrc = fmt.Sprintf("'self' %v", cdnHost)
	}

	scriptSrc := ""
	// Unsafe-inline gets ignored if nonce is provided
	// https://w3c.github.io/webappsec-csp/#allow-all-inline
	if allowInlineScript {
		scriptSrc = "'unsafe-inline'"
	} else {
		scriptSrc = fmt.Sprintf("'nonce-%v'", nonce)
	}

	return []string{
		"default-src 'self'",
		fmt.Sprintf("script-src %v %v www.googletagmanager.com", selfSrc, scriptSrc),
		"frame-src 'self' www.googletagmanager.com",
		fmt.Sprintf("font-src %v cdnjs.cloudflare.com static2.sharepointonline.com fonts.googleapis.com fonts.gstatic.com", selfSrc),
		fmt.Sprintf("style-src %v 'unsafe-inline' cdnjs.cloudflare.com www.googletagmanager.com fonts.googleapis.com", selfSrc),
		// We use data URI to show QR image.
		// We can display external profile picture.
		fmt.Sprintf("img-src %v http: https: data:", selfSrc),
		"object-src 'none'",
		"base-uri 'none'",
		// https://github.com/w3c/webappsec-csp/issues/7
		// 'self' does not include websocket in Safari :(
		fmt.Sprintf("connect-src 'self' https://www.google-analytics.com ws://%s wss://%s", u.Host, u.Host),
		"block-all-mixed-content",
		"frame-ancestors 'none'",
	}, nil
}
