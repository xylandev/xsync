package model

import "time"

type State string

const (
	StateUploading     State = "UPLOADING"
	StateFinalizing    State = "FINALIZING"
	StateReady         State = "READY"
	StateLeased        State = "LEASED"
	StateDeletePending State = "DELETE_PENDING"
	StateDeleted       State = "DELETED"
	StateInterrupted   State = "INTERRUPTED"
	StateCancelled     State = "CANCELLED"
	StateFailed        State = "FAILED"
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
	ID          string            `json:"id"`
	Tenant      string            `json:"tenant"`
	Path        string            `json:"path"`
	BlobPath    string            `json:"blob_path"`
	Size        int64             `json:"size"`
	SHA256      string            `json:"sha256"`
	ETag        string            `json:"etag,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Version     uint64            `json:"version"`
	State       State             `json:"state"`
	QueueKey    string            `json:"queue_key"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	LeaseID     string            `json:"lease_id,omitempty"`
	LeaseClient string            `json:"lease_client,omitempty"`
	LeaseUntil  time.Time         `json:"lease_until,omitempty"`
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
	LeaseUntil time.Time `json:"lease_until"`
}

type Tombstone struct {
	ObjectID  string    `json:"object_id"`
	Tenant    string    `json:"tenant"`
	DeletedAt time.Time `json:"deleted_at"`
}

type Entry struct {
	Path      string    `json:"path"`
	ObjectID  string    `json:"object_id,omitempty"`
	Directory bool      `json:"directory"`
	UpdatedAt time.Time `json:"updated_at"`
}
