package systemfiles

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The binary renders the system files from the very script the provisioner
// runs, so an install and a refresh write the same bytes.
func TestTheEmbeddedProvisionerIsCoreProvisionSh(t *testing.T) {
	core, err := os.ReadFile(filepath.Join("..", "..", "..", "core", "provision", "provision.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Provisioner(), core) {
		t.Fatal("server/internal/systemfiles/provision.sh is not core/provision/provision.sh: cp core/provision/provision.sh server/internal/systemfiles/provision.sh")
	}
}

func TestRunPrintsTheProvisioner(t *testing.T) {
	var out bytes.Buffer
	if code := Run(&out); code != 0 || !bytes.Equal(out.Bytes(), Provisioner()) {
		t.Fatalf("Run = %d, printed %d bytes", code, out.Len())
	}
	if !bytes.HasPrefix(out.Bytes(), []byte("#!/bin/sh\n")) {
		t.Fatal("the provisioner does not start with the line the updater checks")
	}
}
