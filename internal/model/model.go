package model

import "time"

type State string

const (
	StateUploading  State = "UPLOADING"
	StateFinalizing State = "FINALIZING"
	StateReady      State = "READY"
	StateLeased     State = "LEASED"
	// StateDeletePending only appears in catalogs written before schema 2. The
	// migration turns such records into garbage-collection entries.
	StateDeletePending State = "DELETE_PENDING"
	StateInterrupted   State = "INTERRUPTED"
	StateFailed        State = "FAILED"
	// StateHeld is a complete object whose name marks it as a client-side
	// temporary file (for example "*.filepart"). It is not delivered until the
	// uploader renames it to its final name.
	StateHeld State = "HELD"
	// StateParked is a dead-lettered object: it failed delivery too often, or a
	// downloader reported a permanent failure. It stays on disk until an
	// operator or the downloader requeues or deletes it.
	StateParked State = "PARKED"
)

type Upload struct {
	ID          string    `json:"id"`
	Tenant      string    `json:"tenant"`
	Path        string    `json:"path"`
	Protocol    string    `json:"protocol"`
	StagingPath string    `json:"staging_path"`
	State       State     `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Error       string    `json:"error,omitempty"`
}

type ObjectVersion struct {
	ID       string            `json:"id"`
	Tenant   string            `json:"tenant"`
	Path     string            `json:"path"`
	BlobPath string            `json:"blob_path"`
	Size     int64             `json:"size"`
	SHA256   string            `json:"sha256"`
	ETag     string            `json:"etag,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
	Version  uint64            `json:"version"`
	State    State             `json:"state"`
	// QueueSeq is the object's current position in the delivery queue. It
	// changes every time the object is requeued, so stale queue entries can be
	// told apart from the live one.
	QueueSeq uint64 `json:"queue_seq,omitempty"`
	// QueueKey is the pre-schema-2 queue position, kept only so old records
	// decode; the migration rebuilds the queue from QueueSeq.
	QueueKey    string    `json:"queue_key,omitempty"`
	VisibleAt   time.Time `json:"visible_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	LeaseID     string    `json:"lease_id,omitempty"`
	LeaseClient string    `json:"lease_client,omitempty"`
	LeaseUntil  time.Time `json:"lease_until,omitempty"`
	// Attempts counts deliveries handed out; it drives dead-lettering.
	Attempts  int       `json:"attempts,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	ParkedAt  time.Time `json:"parked_at,omitempty"`
	// Retracted marks a leased object whose path was removed or superseded by
	// the uploader while a downloader held it. A commit still succeeds, but a
	// release or lease expiry deletes it instead of requeueing it.
	Retracted bool `json:"retracted,omitempty"`
}

type Claim struct {
	LeaseID    string    `json:"lease_id"`
	ObjectID   string    `json:"object_id"`
	Tenant     string    `json:"tenant"`
	ClientID   string    `json:"client_id"`
	Path       string    `json:"path"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
	Version    uint64    `json:"version"`
	Attempts   int       `json:"attempts"`
	LeaseUntil time.Time `json:"lease_until"`
	// LeaseSeconds is the lease length granted at claim time; a renewal
	// without an explicit length extends by the same amount.
	LeaseSeconds int `json:"lease_seconds,omitempty"`
}

type Tombstone struct {
	ObjectID  string    `json:"object_id"`
	Tenant    string    `json:"tenant"`
	Reason    string    `json:"reason,omitempty"`
	DeletedAt time.Time `json:"deleted_at"`
}

type Entry struct {
	Path      string    `json:"path"`
	Directory bool      `json:"directory"`
	UpdatedAt time.Time `json:"updated_at"`
}
