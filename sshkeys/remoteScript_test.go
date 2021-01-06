package sshkeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateRemoteScript(t *testing.T) {
	home, found := os.LookupEnv("USERPROFILE")
	if !found {
		home = os.Getenv("HOME")
	}

	idRsaPub := filepath.FromSlash(home + "/.ssh/id_rsa.pub")
	v := createRemoteScript(idRsaPub, "icke")

	defer os.Remove(v.LocalPath)

	if !strings.Contains(v.Content, "icke") {
		t.Fatal("content contains no icke", v.Content)
	}

}
