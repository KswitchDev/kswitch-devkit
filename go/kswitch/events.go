package kswitch

import "context"

// EventsService handles governance event queries and statistics.
type EventsService struct {
	client *Client
}

// EventListOptions are query parameters for listing events.
type EventListOptions struct {
	Status    string `json:"status,omitempty"`
	EventType string `json:"event_type,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

// toParams converts EventListOptions to query parameter map.
func (o *EventListOptions) toParams() map[string]string {
	if o == nil {
		return nil
	}
	p := make(map[string]string)
	if o.Status != "" {
		p["status"] = o.Status
	}
	if o.EventType != "" {
		p["event_type"] = o.EventType
	}
	if o.Limit > 0 {
		p["limit"] = itoa(o.Limit)
	}
	return p
}

// List returns governance events with optional filtering.
func (s *EventsService) List(ctx context.Context, opts *EventListOptions) ([]GovernanceEvent, error) {
	var events []GovernanceEvent
	params := opts.toParams()
	err := s.client.doWithParams(ctx, "GET", "/api/v1/events", params, nil, &events)
	return events, err
}

// GetStats returns event outbox delivery statistics.
func (s *EventsService) GetStats(ctx context.Context) (*EventStats, error) {
	var stats EventStats
	err := s.client.do(ctx, "GET", "/api/v1/events/stats", nil, &stats)
	return &stats, err
}
