package node

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"signet/tss"

	"go.etcd.io/bbolt"
)

// openReshareDB opens a dedicated bbolt database for reshare job tracking.
// Used by RemoteKeyManager nodes that don't share a DB with the key store.
func openReshareDB(dataDir string) (*bbolt.DB, error) {
	return bbolt.Open(filepath.Join(dataDir, "reshare.db"), 0600, nil)
}

var (
	bucketReshareJobs = []byte("reshare_jobs")
	bucketReshareDone = []byte("reshare_done")
)

// ReshareJob is the persistent record of a pending reshare for a group.
// One job per group at a time. Written when a membership event is detected;
// deleted when all keys are done.
type ReshareJob struct {
	GroupID      string                   `json:"group_id"`
	OldParties   []tss.PartyID            `json:"old_parties"`
	NewParties   []tss.PartyID            `json:"new_parties"`
	OldThreshold int                      `json:"old_threshold"`
	NewThreshold int                      `json:"new_threshold"`
	KeysTotal    []KeyEntry               `json:"keys_total"`
	StartedAt    time.Time                `json:"started_at"`
	EventType    string                   `json:"event_type"` // "node_added" | "node_removed"
	DeferredEvents []DeferredMembershipEvent `json:"deferred_events,omitempty"`
}

// DeferredMembershipEvent records a membership change that arrived while a
// reshare was already in progress. Processed sequentially after the current
// job completes.
type DeferredMembershipEvent struct {
	EventType  string      `json:"event_type"`
	NodeAddr   string      `json:"node_addr"`
	PartyID    tss.PartyID `json:"party_id"`
	DetectedAt time.Time   `json:"detected_at"`
}

// ReshareKeyRecord is written per-key when that key's reshare completes.
type ReshareKeyRecord struct {
	CompletedAt time.Time `json:"completed_at"`
	ByNode      string    `json:"by_node"`
	OldOnly     bool      `json:"old_only"`
}

// ReshareStore manages the reshare_jobs and reshare_done bbolt buckets.
// It shares the same bbolt.DB as the KeyShardStore (keyshards.db).
type ReshareStore struct {
	db *bbolt.DB
}

// NewReshareStore creates a ReshareStore using an existing bbolt.DB.
// The db is typically the same instance used by KeyShardStore.
func NewReshareStore(db *bbolt.DB) (*ReshareStore, error) {
	err := db.Update(func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketReshareJobs); err != nil {
			return fmt.Errorf("create reshare_jobs bucket: %w", err)
		}
		if _, err := tx.CreateBucketIfNotExists(bucketReshareDone); err != nil {
			return fmt.Errorf("create reshare_done bucket: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &ReshareStore{db: db}, nil
}

// PutJob writes or updates a ReshareJob for a group.
func (rs *ReshareStore) PutJob(job *ReshareJob) error {
	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal reshare job: %w", err)
	}
	return rs.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketReshareJobs)
		return b.Put([]byte(job.GroupID), data)
	})
}

// GetJob returns the ReshareJob for a group, or nil if none exists.
func (rs *ReshareStore) GetJob(groupID string) (*ReshareJob, error) {
	var job *ReshareJob
	err := rs.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketReshareJobs)
		data := b.Get([]byte(groupID))
		if data == nil {
			return nil
		}
		job = new(ReshareJob)
		return json.Unmarshal(data, job)
	})
	return job, err
}

// DeleteJob removes the ReshareJob for a group.
func (rs *ReshareStore) DeleteJob(groupID string) error {
	return rs.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketReshareJobs)
		return b.Delete([]byte(groupID))
	})
}

// ListJobs returns all group IDs that have a pending reshare job.
func (rs *ReshareStore) ListJobs() ([]string, error) {
	var groups []string
	err := rs.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketReshareJobs)
		return b.ForEach(func(k, _ []byte) error {
			groups = append(groups, string(k))
			return nil
		})
	})
	return groups, err
}

// PutKeyDone records that a single key's reshare has completed.
func (rs *ReshareStore) PutKeyDone(groupID, keyID string, rec *ReshareKeyRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal reshare key record: %w", err)
	}
	return rs.db.Update(func(tx *bbolt.Tx) error {
		root := tx.Bucket(bucketReshareDone)
		grp, err := root.CreateBucketIfNotExists([]byte(groupID))
		if err != nil {
			return err
		}
		return grp.Put([]byte(keyID), data)
	})
}

// IsKeyDone returns true if a key's reshare has been recorded as complete.
func (rs *ReshareStore) IsKeyDone(groupID, keyID string) (bool, error) {
	var done bool
	err := rs.db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket(bucketReshareDone)
		grp := root.Bucket([]byte(groupID))
		if grp == nil {
			return nil
		}
		done = grp.Get([]byte(keyID)) != nil
		return nil
	})
	return done, err
}

// DeleteKeyDone removes the done marker for a single key. Used when rolling
// back a partial reshare on retry.
func (rs *ReshareStore) DeleteKeyDone(groupID, keyID string) error {
	return rs.db.Update(func(tx *bbolt.Tx) error {
		root := tx.Bucket(bucketReshareDone)
		grp := root.Bucket([]byte(groupID))
		if grp == nil {
			return nil
		}
		return grp.Delete([]byte(keyID))
	})
}

// CountKeysDone returns how many keys are marked done for a group.
func (rs *ReshareStore) CountKeysDone(groupID string) (int, error) {
	var count int
	err := rs.db.View(func(tx *bbolt.Tx) error {
		root := tx.Bucket(bucketReshareDone)
		grp := root.Bucket([]byte(groupID))
		if grp == nil {
			return nil
		}
		return grp.ForEach(func(_, _ []byte) error {
			count++
			return nil
		})
	})
	return count, err
}

// ClearKeysDone deletes all reshare_done entries for a group.
func (rs *ReshareStore) ClearKeysDone(groupID string) error {
	return rs.db.Update(func(tx *bbolt.Tx) error {
		root := tx.Bucket(bucketReshareDone)
		if root.Bucket([]byte(groupID)) != nil {
			return root.DeleteBucket([]byte(groupID))
		}
		return nil
	})
}
