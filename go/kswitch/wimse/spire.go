// Package wimse implements WIMSE delegation assertion building for KSwitch.
//
// This file provides the SPIRE Workload API client for fetching SVIDs
// used in WIMSE assertion signing. The SPIRE client is co-located in
// the wimse package because it is specific to WIMSE signing in the Go SDK.

package wimse

import (
	"crypto"
	"fmt"
	"os"
)

// Default SPIRE Workload API socket path.
const defaultSpireSocketPath = "unix:///run/spiffe/sockets/agent.sock"

// SVIDBundle holds the private key and SPIFFE ID from a single SVID fetch.
// Key and ID are atomic — they come from the same SVID to avoid rotation races.
type SVIDBundle struct {
	PrivateKey crypto.PrivateKey // *ecdsa.PrivateKey (EC P-256)
	SpiffeID   string
}

// SPIREUnavailableError is returned when the SPIRE Workload API socket is
// absent or unreachable.
type SPIREUnavailableError struct {
	Message string
}

func (e *SPIREUnavailableError) Error() string { return e.Message }

// fetchSVIDFunc is the internal function pointer used by FetchSVID.
// Tests replace this to inject mock SVIDs without requiring a live SPIRE agent.
var fetchSVIDFunc = defaultFetchSVID

// FetchSVID retrieves this workload's SVID private key and SPIFFE ID.
//
// In production this calls the SPIRE Workload API via gRPC. For now it
// returns SPIREUnavailableError if the socket does not exist.
//
// Tests override fetchSVIDFunc to inject mock SVIDs.
func FetchSVID() (*SVIDBundle, error) {
	return fetchSVIDFunc()
}

func defaultFetchSVID() (*SVIDBundle, error) {
	socketPath := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if socketPath == "" {
		socketPath = defaultSpireSocketPath
	}

	// Strip unix:// prefix for filesystem check.
	fsPath := socketPath
	if len(fsPath) > 7 && fsPath[:7] == "unix://" {
		fsPath = fsPath[7:]
	}

	if _, err := os.Stat(fsPath); os.IsNotExist(err) {
		return nil, &SPIREUnavailableError{
			Message: fmt.Sprintf(
				"SPIRE Workload API socket not found at %s. "+
					"Ensure the SPIRE Agent DaemonSet is running and the socket is mounted.",
				socketPath,
			),
		}
	}

	// Production: gRPC to SPIRE Workload API would go here.
	// For now, return unavailable since we cannot connect without the agent.
	return nil, &SPIREUnavailableError{
		Message: fmt.Sprintf(
			"SPIRE Workload API gRPC client not yet implemented (socket: %s)",
			socketPath,
		),
	}
}
