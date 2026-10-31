// SPDX-FileCopyrightText: 2026 Motrice AB
//
// SPDX-License-Identifier: EUPL-1.2

// Package archguard_test watches the hexagonal layering.
//
// The dependency direction is cmd -> app -> domain <- adapters. The rules below
// are not style preferences: they are what makes the domain testable without a
// network or certificates, and what stops protocol details from seeping into
// the business rules. Break them and the build fails, not a code review.
package archguard_test

import (
	"errors"
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/motrice/smartcard-op"

// effectPackages are standard library packages that open files, start
// subprocesses or talk to the network. They belong in an adapter, never in the
// domain or in a use case.
var effectPackages = []string{
	"net",
	"net/http",
	"os",
	"os/exec",
	"database/sql",
	"log",
	"log/slog",
}

// rules state, per layer, which imports are forbidden.
var rules = map[string]struct {
	forbiddenPrefixes []string
	forbiddenExact    []string
}{
	"internal/domain": {
		forbiddenPrefixes: []string{
			module + "/internal/app",
			module + "/internal/adapters",
			module + "/cmd",
		},
		forbiddenExact: effectPackages,
	},
	"internal/app": {
		forbiddenPrefixes: []string{
			module + "/internal/adapters",
			module + "/cmd",
		},
		forbiddenExact: effectPackages,
	},
	// Adapters satisfy the ports structurally. Were they to import app the
	// dependency arrow would reverse and the notion of a port would stop
	// meaning anything.
	"internal/adapters": {
		forbiddenPrefixes: []string{
			module + "/internal/app",
			module + "/cmd",
		},
	},
}

func TestLayerRulesHold(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)

	for layer, rule := range rules {
		t.Run(layer, func(t *testing.T) {
			t.Parallel()

			for _, dir := range packageDirs(t, filepath.Join(root, layer)) {
				pkg, err := build.ImportDir(dir, 0)
				if err != nil {
					if _, isNoGo := errors.AsType[*build.NoGoError](err); isNoGo {
						continue
					}

					t.Fatalf("could not read %s: %v", dir, err)
				}

				relative, _ := filepath.Rel(root, dir)

				for _, imported := range pkg.Imports {
					for _, forbidden := range rule.forbiddenPrefixes {
						if strings.HasPrefix(imported, forbidden) {
							t.Errorf("%s imports %s; %s must not depend on it",
								relative, imported, layer)
						}
					}

					for _, forbidden := range rule.forbiddenExact {
						if imported == forbidden {
							t.Errorf("%s imports %s; effects belong in an adapter",
								relative, imported)
						}
					}
				}
			}
		})
	}
}

// The domain must build and test without a single third-party dependency. The
// day that stops being true, a protocol or library detail has moved into the
// business rules.
func TestDomainDependsOnlyOnTheStandardLibrary(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)

	for _, dir := range packageDirs(t, filepath.Join(root, "internal/domain")) {
		pkg, err := build.ImportDir(dir, 0)
		if err != nil {
			continue
		}

		relative, _ := filepath.Rel(root, dir)

		for _, imported := range pkg.Imports {
			if strings.HasPrefix(imported, module) {
				continue
			}

			if strings.Contains(strings.SplitN(imported, "/", 2)[0], ".") {
				t.Errorf("%s imports the third-party package %s", relative, imported)
			}
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("could not read the working directory: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("found no go.mod up the tree")
		}

		dir = parent
	}
}

// packageDirs returns the layer's own directory and every subdirectory, except
// testdata.
func packageDirs(t *testing.T, root string) []string {
	t.Helper()

	var dirs []string

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !entry.IsDir() {
			return nil
		}

		if entry.Name() == "testdata" {
			return filepath.SkipDir
		}

		dirs = append(dirs, path)

		return nil
	})
	if err != nil {
		t.Fatalf("could not walk %s: %v", root, err)
	}

	return dirs
}
