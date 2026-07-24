package cutoverroster

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketOperators = []byte("operators")
	bucketInstances = []byte("instances")
)

// operatorRecord is the persisted per-operator central state. Central state is
// only advanced by resolution or verified quarantine; local eviction, reporter
// restarts, quiet counters, or service-discovery churn never resolve it.
type operatorRecord struct {
	OperatorAddress string      `json:"operator_address"`
	StakingProvider string      `json:"staking_provider"`
	Status          FleetStatus `json:"status"`
	FirstSeenBlock  uint64      `json:"first_seen_block"`
	LastSeenBlock   uint64      `json:"last_seen_block"`
	Reason          string      `json:"reason"`
	LastLegacyBlock uint64      `json:"last_legacy_block"`
	LastLegacyAt    time.Time   `json:"last_legacy_at"`
	ResolvedAt      time.Time   `json:"resolved_at"`
}

// instanceRecord is the persisted per-instance report history and the
// authoritative inventory expectations that were last reconciled for the
// instance. The per-instance expectations (ceremony eligibility, staking
// provider, and expected revision/epoch/digest) are persisted so an audit or a
// restarted collector can see exactly what each instance was expected to report,
// not only whether it reported.
type instanceRecord struct {
	InstanceID        string          `json:"instance_id"`
	OperatorAddress   string          `json:"operator_address"`
	LatestReport      *InstanceReport `json:"latest_report,omitempty"`
	ConsecutiveExact  uint            `json:"consecutive_exact"`
	ConsecutiveMissed uint            `json:"consecutive_missed"`
	HasQuarantine     bool            `json:"has_quarantine"`
	QuarantineRef     string          `json:"quarantine_ref,omitempty"`
	// LastReporterRevision is the highest accepted InstanceReport.ReporterRevision
	// for this instance. It guards against replayed or downgraded attestations.
	LastReporterRevision uint64 `json:"last_reporter_revision"`

	// Per-instance authoritative inventory expectations, last observed for the
	// instance. They are recorded for auditability so a reader can see the exact
	// per-instance expected artifact identity rather than only the collector-wide
	// configured expectation.
	CeremonyEligible    bool   `json:"ceremony_eligible"`
	StakingProvider     string `json:"staking_provider,omitempty"`
	ExpectedRevision    string `json:"expected_revision,omitempty"`
	ExpectedEpoch       string `json:"expected_epoch,omitempty"`
	ExpectedImageDigest string `json:"expected_image_digest,omitempty"`

	// ReportedThisCycle records whether a report from this instance was accepted
	// in the most recent collection cycle. It is deliberately distinct from
	// "LatestReport != nil" (which means "ever reported"): the unresolved-operator
	// log and the per-instance status use this to count only instances that
	// reported in the current cycle, not historical reporters.
	ReportedThisCycle bool `json:"reported_this_cycle"`

	// DisappearedFromDiscovery records whether the instance was absent from the
	// production service-discovery target set in the most recent cycle while still
	// present in the authoritative inventory. Disappearance from service discovery
	// is offline_unknown and never resolves central state.
	DisappearedFromDiscovery bool `json:"disappeared_from_discovery"`
}

// Store is the transactional bbolt persistence for the fleet collector.
type Store struct {
	db *bolt.DB
}

// OpenStore opens (creating if needed) the bbolt database at path, creating the
// parent directory and the required buckets.
func OpenStore(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("store path must not be empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create store directory [%s]: %w", dir, err)
	}

	// #nosec G304 -- path is the operator-supplied database location for the
	// monitoring tool; it is intentionally configurable.
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("cannot open store [%s]: %w", path, err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketOperators); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(bucketInstances); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("cannot initialize store buckets: %w", err)
	}

	return &Store{db: db}, nil
}

// LoadOperators reads all persisted operator records.
func (s *Store) LoadOperators() (map[string]*operatorRecord, error) {
	operators := make(map[string]*operatorRecord)
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketOperators)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			record := &operatorRecord{}
			if err := json.Unmarshal(v, record); err != nil {
				return fmt.Errorf("cannot decode operator [%s]: %w", k, err)
			}
			operators[string(k)] = record
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return operators, nil
}

// LoadInstances reads all persisted instance records.
func (s *Store) LoadInstances() (map[string]*instanceRecord, error) {
	instances := make(map[string]*instanceRecord)
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketInstances)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			record := &instanceRecord{}
			if err := json.Unmarshal(v, record); err != nil {
				return fmt.Errorf("cannot decode instance [%s]: %w", k, err)
			}
			instances[string(k)] = record
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return instances, nil
}

// Save transactionally rewrites the operator and instance buckets so that they
// exactly match the supplied maps, including deletions (used for the 30-day
// resolved purge). The entire write is a single bbolt transaction.
func (s *Store) Save(
	operators map[string]*operatorRecord,
	instances map[string]*instanceRecord,
) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := syncBucket(tx, bucketOperators, encodeOperators(operators)); err != nil {
			return err
		}
		return syncBucket(tx, bucketInstances, encodeInstances(instances))
	})
}

// Close closes the underlying database. It is safe to call on a nil store.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func encodeOperators(operators map[string]*operatorRecord) map[string][]byte {
	encoded := make(map[string][]byte, len(operators))
	for key, record := range operators {
		// Errors are impossible for these plain structs; ignore defensively.
		data, _ := json.Marshal(record)
		encoded[key] = data
	}
	return encoded
}

func encodeInstances(instances map[string]*instanceRecord) map[string][]byte {
	encoded := make(map[string][]byte, len(instances))
	for key, record := range instances {
		data, _ := json.Marshal(record)
		encoded[key] = data
	}
	return encoded
}

// syncBucket makes the bucket contents equal to `desired`, deleting any keys
// not present in it.
func syncBucket(tx *bolt.Tx, name []byte, desired map[string][]byte) error {
	bucket, err := tx.CreateBucketIfNotExists(name)
	if err != nil {
		return err
	}

	// Delete keys that are no longer present.
	var toDelete [][]byte
	err = bucket.ForEach(func(k, _ []byte) error {
		if _, ok := desired[string(k)]; !ok {
			key := make([]byte, len(k))
			copy(key, k)
			toDelete = append(toDelete, key)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, key := range toDelete {
		if err := bucket.Delete(key); err != nil {
			return err
		}
	}

	// Upsert current keys.
	for key, value := range desired {
		if err := bucket.Put([]byte(key), value); err != nil {
			return err
		}
	}

	return nil
}
