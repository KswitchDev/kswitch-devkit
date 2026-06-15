// curl.go — synchronous HTTP via system curl (avoids goroutine complexity).
// Used only as a fallback when the JWKS disk cache is missing.
package tokens

import (
	"os/exec"
	"strings"
)

// execCurl fetches url synchronously using the system curl binary.
// Returns ("", err) if curl is not available or the request fails.
func execCurl(url string) (string, error) {
	cmd := exec.Command("curl", "-sk", "--max-time", "3", url) // #nosec G204 — url is a well-known endpoint set by admin
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
