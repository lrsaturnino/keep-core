package participation

import (
	"errors"
	"io/fs"
	"testing"
)

type quiescencePersistenceRecorder struct {
	deletedDirectory string
	deletedName      string
	deleteErr        error
	saved            []byte
}

func (p *quiescencePersistenceRecorder) Save(
	data []byte,
	directory string,
	name string,
) error {
	p.saved = append([]byte(nil), data...)
	return nil
}

func (p *quiescencePersistenceRecorder) Delete(
	directory string,
	name string,
) error {
	p.deletedDirectory = directory
	p.deletedName = name
	return p.deleteErr
}

func TestNewPersistenceQuiescenceSnapshotRecorder_InvalidatesPriorRun(
	t *testing.T,
) {
	persistence := &quiescencePersistenceRecorder{}

	if _, err := NewPersistenceQuiescenceSnapshotRecorder(
		persistence,
	); err != nil {
		t.Fatal(err)
	}

	if persistence.deletedDirectory !=
		QuiescenceSnapshotStorageDirectory ||
		persistence.deletedName != QuiescenceSnapshotStorageFile {
		t.Errorf(
			"unexpected invalidated record [%s/%s]",
			persistence.deletedDirectory,
			persistence.deletedName,
		)
	}
}

func TestNewPersistenceQuiescenceSnapshotRecorder_MissingPriorRunIsAllowed(
	t *testing.T,
) {
	persistence := &quiescencePersistenceRecorder{
		deleteErr: fs.ErrNotExist,
	}

	if _, err := NewPersistenceQuiescenceSnapshotRecorder(
		persistence,
	); err != nil {
		t.Fatal(err)
	}
}

func TestNewPersistenceQuiescenceSnapshotRecorder_DeleteFailureIsFatal(
	t *testing.T,
) {
	deleteErr := errors.New("delete failed")
	persistence := &quiescencePersistenceRecorder{
		deleteErr: deleteErr,
	}

	if _, err := NewPersistenceQuiescenceSnapshotRecorder(
		persistence,
	); !errors.Is(err, deleteErr) {
		t.Fatalf("expected delete failure, got [%v]", err)
	}
}
