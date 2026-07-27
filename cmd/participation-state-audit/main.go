// Command participation-state-audit classifies a stopped node's persisted
// protocol state for the rollback barrier, without exposing private material.
//
// It inventories the keystore and work namespaces with checksums of the
// at-rest (encrypted) bytes, interprets the beacon active-group namespace and
// the beacon quarantine namespace when the storage password is supplied, and
// reports every inconsistency it finds: quarantined outputs missing either
// their membership record or their audit metadata, records that fail to
// decrypt or decode, and quarantine state visible to the active-group scan.
//
// The tool MUST run against a snapshot copy of the node's storage, never the
// live directory: opening the standard persistence handles creates their
// bookkeeping subdirectories and probes write permission, and a rollback
// audit must not mutate the original evidence.
//
// Chain reconciliation — on-chain wallet registration and beacon group
// acceptance — is deliberately not performed here: this is the offline
// classification step, and its output never authorizes activating any
// quarantined material by itself.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/keep-network/keep-core/config"
	"github.com/keep-network/keep-core/pkg/beacon/registry"
	"github.com/keep-network/keep-core/pkg/storage"
)

// manifestSchemaVersion versions the audit manifest document.
const manifestSchemaVersion = uint32(1)

// The audited namespaces, relative to the storage root. The beacon quarantine
// namespace is a sibling of the active beacon keystore precisely so the
// active-group scan cannot read it; the audit re-verifies that separation.
const (
	beaconKeystoreNamespace   = "keystore/beacon"
	beaconQuarantineNamespace = "keystore/beacon-quarantine"
	tbtcKeystoreNamespace     = "keystore/tbtc"
	tbtcWorkNamespace         = "work/tbtc"
)

type fileRecord struct {
	// Path is relative to the storage root.
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
	// SHA256 is the checksum of the at-rest bytes. Key-holding files are
	// encrypted at rest, so the checksum commits to the snapshot content
	// without exposing key material.
	SHA256 string `json:"sha256"`
}

type namespaceInventory struct {
	Name    string       `json:"name"`
	Present bool         `json:"present"`
	Files   []fileRecord `json:"files"`
}

type beaconMembershipRecord struct {
	GroupPublicKey string `json:"group_public_key"`
	MemberIndex    uint8  `json:"member_index"`
	ChannelName    string `json:"channel_name"`
}

type beaconQuarantineRecord struct {
	registry.QuarantinedSignerMetadata

	// HasMembershipRecord reports whether the preserved membership bytes
	// accompany the metadata; metadata without the membership means the key
	// material was lost and the record is evidence only.
	HasMembershipRecord bool `json:"has_membership_record"`
}

type manifest struct {
	SchemaVersion uint32    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	// Interpreted reports whether the storage password was supplied and the
	// beacon namespaces were decoded; without it the manifest is a raw
	// inventory only.
	Interpreted bool                 `json:"interpreted"`
	Namespaces  []namespaceInventory `json:"namespaces"`

	BeaconActiveMemberships  []beaconMembershipRecord `json:"beacon_active_memberships,omitempty"`
	BeaconQuarantinedOutputs []beaconQuarantineRecord `json:"beacon_quarantined_outputs,omitempty"`

	// Findings lists every inconsistency; an empty list with Interpreted true
	// means the namespaces are internally consistent.
	Findings []string `json:"findings"`
	// Consistent is true when interpretation ran and produced no findings.
	// It classifies namespace integrity only.
	Consistent bool `json:"consistent"`
	// ChainReconciliation records that the online reconciliation step — chain
	// registration and acceptance checks — is out of this tool's scope.
	ChainReconciliation string `json:"chain_reconciliation"`
}

func main() {
	var storageDir string
	var outputPath string

	flag.StringVar(
		&storageDir,
		"storage-snapshot",
		"",
		"path to a snapshot copy of the node's storage directory (required); "+
			"never point this at a live node's storage",
	)
	flag.StringVar(
		&outputPath,
		"output",
		"",
		"write the manifest to this file instead of stdout",
	)
	flag.Parse()

	if storageDir == "" {
		fmt.Fprintln(os.Stderr, "the --storage-snapshot flag is required")
		flag.Usage()
		os.Exit(2)
	}

	password := os.Getenv(config.EthereumPasswordEnvVariable)

	auditManifest, err := runAudit(storageDir, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit failed: [%v]\n", err)
		os.Exit(1)
	}

	encoded, err := json.MarshalIndent(auditManifest, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot encode the manifest: [%v]\n", err)
		os.Exit(1)
	}
	encoded = append(encoded, '\n')

	if outputPath != "" {
		if err := os.WriteFile(outputPath, encoded, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "cannot write the manifest: [%v]\n", err)
			os.Exit(1)
		}
	} else {
		os.Stdout.Write(encoded)
	}

	if !auditManifest.Consistent {
		os.Exit(3)
	}
}

// runAudit produces the audit manifest for the given storage snapshot. An
// empty password skips interpretation and produces a raw inventory.
func runAudit(storageDir string, password string) (*manifest, error) {
	info, err := os.Stat(storageDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read the storage snapshot: [%w]", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf(
			"the storage snapshot [%s] is not a directory",
			storageDir,
		)
	}

	auditManifest := &manifest{
		SchemaVersion:       manifestSchemaVersion,
		GeneratedAt:         time.Now().UTC(),
		ChainReconciliation: "not_performed",
	}

	for _, namespace := range []string{
		beaconKeystoreNamespace,
		beaconQuarantineNamespace,
		tbtcKeystoreNamespace,
		tbtcWorkNamespace,
	} {
		inventory, err := inventoryNamespace(storageDir, namespace)
		if err != nil {
			return nil, err
		}
		auditManifest.Namespaces = append(auditManifest.Namespaces, inventory)
	}

	if password != "" {
		auditManifest.Interpreted = true
		if err := interpretBeaconNamespaces(
			storageDir,
			password,
			auditManifest,
		); err != nil {
			return nil, err
		}
	} else {
		auditManifest.Findings = append(
			auditManifest.Findings,
			fmt.Sprintf(
				"interpretation skipped: the [%s] environment variable is "+
					"not set",
				config.EthereumPasswordEnvVariable,
			),
		)
	}

	auditManifest.Consistent = auditManifest.Interpreted &&
		len(auditManifest.Findings) == 0

	return auditManifest, nil
}

// inventoryNamespace walks one namespace and records every regular file with
// the checksum of its at-rest bytes. A missing namespace is recorded as
// absent, not an error: a node that never quarantined anything has no
// quarantine directory.
func inventoryNamespace(
	storageDir string,
	namespace string,
) (namespaceInventory, error) {
	inventory := namespaceInventory{Name: namespace}

	root := filepath.Join(storageDir, filepath.FromSlash(namespace))
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return inventory, nil
	} else if err != nil {
		return inventory, fmt.Errorf(
			"cannot read namespace [%s]: [%w]",
			namespace,
			err,
		)
	}
	inventory.Present = true

	err := filepath.WalkDir(root, func(
		path string,
		entry fs.DirEntry,
		err error,
	) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("cannot read [%s]: [%w]", path, err)
		}
		checksum := sha256.Sum256(content)

		relative, err := filepath.Rel(storageDir, path)
		if err != nil {
			return err
		}

		inventory.Files = append(inventory.Files, fileRecord{
			Path:   filepath.ToSlash(relative),
			Bytes:  int64(len(content)),
			SHA256: hex.EncodeToString(checksum[:]),
		})
		return nil
	})
	if err != nil {
		return inventory, fmt.Errorf(
			"cannot inventory namespace [%s]: [%w]",
			namespace,
			err,
		)
	}

	sort.Slice(inventory.Files, func(i, j int) bool {
		return inventory.Files[i].Path < inventory.Files[j].Path
	})

	return inventory, nil
}

// interpretBeaconNamespaces decodes the beacon active and quarantine
// namespaces through the standard encrypted persistence handles and records
// every decode failure and cross-record inconsistency as a finding.
func interpretBeaconNamespaces(
	storageDir string,
	password string,
	auditManifest *manifest,
) error {
	diskStorage, err := storage.Initialize(
		storage.Config{Dir: storageDir},
		password,
	)
	if err != nil {
		return fmt.Errorf("cannot open the storage snapshot: [%w]", err)
	}

	activeHandle, err := diskStorage.InitializeKeyStorePersistence("beacon")
	if err != nil {
		return fmt.Errorf(
			"cannot open the beacon keystore namespace: [%w]",
			err,
		)
	}

	quarantineHandle, err := diskStorage.InitializeKeyStorePersistence(
		"beacon-quarantine",
	)
	if err != nil {
		return fmt.Errorf(
			"cannot open the beacon quarantine namespace: [%w]",
			err,
		)
	}

	finding := func(format string, args ...interface{}) {
		auditManifest.Findings = append(
			auditManifest.Findings,
			fmt.Sprintf(format, args...),
		)
	}

	// Active namespace: every descriptor must decode as a membership — that
	// is exactly what the client's own active-group scan assumes on start.
	activeData, activeErrors := activeHandle.ReadAll()
	activeDone := make(chan struct{})
	go func() {
		defer close(activeDone)
		for err := range activeErrors {
			finding("beacon active namespace read error: [%v]", err)
		}
	}()
	for descriptor := range activeData {
		content, err := descriptor.Content()
		if err != nil {
			finding(
				"beacon active record [%s/%s] cannot be decrypted: [%v]",
				descriptor.Directory(),
				descriptor.Name(),
				err,
			)
			continue
		}

		membership := &registry.Membership{}
		if err := membership.Unmarshal(content); err != nil {
			finding(
				"beacon active record [%s/%s] cannot be decoded as a "+
					"membership: [%v]",
				descriptor.Directory(),
				descriptor.Name(),
				err,
			)
			continue
		}

		auditManifest.BeaconActiveMemberships = append(
			auditManifest.BeaconActiveMemberships,
			beaconMembershipRecord{
				GroupPublicKey: hex.EncodeToString(
					membership.Signer.GroupPublicKeyBytesCompressed(),
				),
				MemberIndex: uint8(membership.Signer.MemberID()),
				ChannelName: membership.ChannelName,
			},
		)
	}
	<-activeDone

	// Quarantine namespace: metadata and membership records pair up by
	// directory and member suffix; either half alone is a finding.
	type quarantineEntry struct {
		metadata      *registry.QuarantinedSignerMetadata
		hasMembership bool
	}
	quarantineEntries := make(map[string]*quarantineEntry)
	entryFor := func(directory, name, prefix string) *quarantineEntry {
		key := directory + "/" + strings.TrimPrefix(name, prefix)
		if _, ok := quarantineEntries[key]; !ok {
			quarantineEntries[key] = &quarantineEntry{}
		}
		return quarantineEntries[key]
	}

	quarantineData, quarantineErrors := quarantineHandle.ReadAll()
	quarantineDone := make(chan struct{})
	go func() {
		defer close(quarantineDone)
		for err := range quarantineErrors {
			finding("beacon quarantine namespace read error: [%v]", err)
		}
	}()
	for descriptor := range quarantineData {
		content, err := descriptor.Content()
		if err != nil {
			finding(
				"beacon quarantine record [%s/%s] cannot be decrypted: [%v]",
				descriptor.Directory(),
				descriptor.Name(),
				err,
			)
			continue
		}

		switch {
		case strings.HasPrefix(descriptor.Name(), "metadata_"):
			metadata := &registry.QuarantinedSignerMetadata{}
			if err := json.Unmarshal(content, metadata); err != nil {
				finding(
					"beacon quarantine metadata [%s/%s] cannot be decoded: "+
						"[%v]",
					descriptor.Directory(),
					descriptor.Name(),
					err,
				)
				continue
			}
			entryFor(
				descriptor.Directory(),
				descriptor.Name(),
				"metadata_",
			).metadata = metadata
		case strings.HasPrefix(descriptor.Name(), "membership_"):
			membership := &registry.Membership{}
			if err := membership.Unmarshal(content); err != nil {
				finding(
					"beacon quarantine membership [%s/%s] cannot be decoded: "+
						"[%v]",
					descriptor.Directory(),
					descriptor.Name(),
					err,
				)
				continue
			}
			entryFor(
				descriptor.Directory(),
				descriptor.Name(),
				"membership_",
			).hasMembership = true
		default:
			finding(
				"beacon quarantine record [%s/%s] has an unknown name",
				descriptor.Directory(),
				descriptor.Name(),
			)
		}
	}
	<-quarantineDone

	keys := make([]string, 0, len(quarantineEntries))
	for key := range quarantineEntries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		entry := quarantineEntries[key]

		if entry.metadata == nil {
			finding(
				"beacon quarantine output [%s] has a membership record "+
					"without audit metadata",
				key,
			)
			continue
		}
		if !entry.hasMembership {
			finding(
				"beacon quarantine output [%s] has audit metadata without "+
					"a membership record; the key material was not preserved",
				key,
			)
		}

		auditManifest.BeaconQuarantinedOutputs = append(
			auditManifest.BeaconQuarantinedOutputs,
			beaconQuarantineRecord{
				QuarantinedSignerMetadata: *entry.metadata,
				HasMembershipRecord:       entry.hasMembership,
			},
		)
	}

	sortRecords(auditManifest)

	return nil
}

// sortRecords orders the interpreted records deterministically so two audits
// of the same snapshot produce byte-identical manifests apart from the
// generation time.
func sortRecords(auditManifest *manifest) {
	sort.Slice(auditManifest.BeaconActiveMemberships, func(i, j int) bool {
		left := auditManifest.BeaconActiveMemberships[i]
		right := auditManifest.BeaconActiveMemberships[j]
		if left.GroupPublicKey != right.GroupPublicKey {
			return left.GroupPublicKey < right.GroupPublicKey
		}
		return left.MemberIndex < right.MemberIndex
	})
	sort.Slice(auditManifest.BeaconQuarantinedOutputs, func(i, j int) bool {
		left := auditManifest.BeaconQuarantinedOutputs[i]
		right := auditManifest.BeaconQuarantinedOutputs[j]
		if left.GroupPublicKey != right.GroupPublicKey {
			return left.GroupPublicKey < right.GroupPublicKey
		}
		return left.MemberIndex < right.MemberIndex
	})
}
