// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestParseContainerdConfig(t *testing.T) {
	tests := []struct {
		name         string
		toml         string
		wantDisabled bool
		wantEnabled  bool
		wantShimPath string
	}{
		{
			name: "enable_criu explicitly false",
			toml: `
version = 2
[plugins."io.containerd.cri.v1.runtime"]
  enable_criu = false
  shim_path = "/usr/local/bin"
`,
			wantDisabled: true,
			wantShimPath: "/usr/local/bin",
		},
		{
			name: "enable_criu explicitly true",
			toml: `
version = 2
[plugins."io.containerd.cri.v1.runtime"]
  enable_criu = true
`,
			wantEnabled: true,
		},
		{
			name: "enable_criu omitted defaults to nil",
			toml: `
version = 2
[plugins."io.containerd.cri.v1.runtime"]
  sandbox_image = "registry.k8s.io/pause:3.9"
`,
		},
		{
			name: "custom PATH in env slice",
			toml: `
[plugins."io.containerd.cri.v1.runtime"]
  env = ["PATH=/opt/containerd/bin:/usr/bin", "FOO=BAR"]
`,
			wantShimPath: "/opt/containerd/bin:/usr/bin",
		},
		{
			name: "comments and inline comments ignored",
			toml: `
# enable_criu = false in comment
enable_criu = true # inline comment
`,
			wantEnabled: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enableCRIU, shimPath, err := ParseContainerdConfig([]byte(tc.toml))
			if err != nil {
				t.Fatalf("ParseContainerdConfig: %v", err)
			}
			if tc.wantDisabled {
				if enableCRIU == nil || *enableCRIU != false {
					t.Fatalf("want enableCRIU == false, got %v", enableCRIU)
				}
			}
			if tc.wantEnabled {
				if enableCRIU == nil || *enableCRIU != true {
					t.Fatalf("want enableCRIU == true, got %v", enableCRIU)
				}
			}
			if !tc.wantDisabled && !tc.wantEnabled && enableCRIU != nil {
				t.Fatalf("want enableCRIU == nil, got %v", *enableCRIU)
			}
			if tc.wantShimPath != "" && shimPath != tc.wantShimPath {
				t.Fatalf("want shimPath %q, got %q", tc.wantShimPath, shimPath)
			}
		})
	}
}

func TestParseProcessEnviron(t *testing.T) {
	envData := []byte("USER=root\x00PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\x00HOME=/root\x00")
	got := ParseProcessEnviron(envData)
	want := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
	if got != want {
		t.Fatalf("ParseProcessEnviron = %q, want %q", got, want)
	}

	empty := ParseProcessEnviron([]byte("USER=root\x00HOME=/root\x00"))
	if empty != "" {
		t.Fatalf("expected empty PATH, got %q", empty)
	}
}

func TestResolveCRIUPath(t *testing.T) {
	tmpDir := t.TempDir()
	binDir1 := filepath.Join(tmpDir, "bin1")
	binDir2 := filepath.Join(tmpDir, "bin2")
	_ = os.MkdirAll(binDir1, 0o755)
	_ = os.MkdirAll(binDir2, 0o755)

	// Non-executable criu in binDir1
	nonExec := filepath.Join(binDir1, "criu")
	if err := os.WriteFile(nonExec, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Executable criu in binDir2
	execPath := filepath.Join(binDir2, "criu")
	if err := os.WriteFile(execPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Search PATH with only binDir1 should not find criu
	if got := ResolveCRIUPath(binDir1); got != "" {
		t.Fatalf("expected non-executable criu to be rejected, got %q", got)
	}

	// Search PATH with binDir1:binDir2 should resolve binDir2/criu
	searchPath := binDir1 + string(filepath.ListSeparator) + binDir2
	if got := ResolveCRIUPath(searchPath); got != execPath {
		t.Fatalf("ResolveCRIUPath = %q, want %q", got, execPath)
	}
}

func TestParseCRIUVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{input: "Version: 3.19", want: 31900},
		{input: "Version: 4.0", want: 40000},
		{input: "Version: 3.16.2", want: 31602},
		{input: "3.19-2", want: 31900},
		{input: "v3.16.0", want: 31600},
		{input: "Version: 3.15", want: 31500},
		{input: "invalid output", wantErr: true},
	}

	for _, tc := range tests {
		got, err := ParseCRIUVersion(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseCRIUVersion(%q) want error, got nil", tc.input)
			}
		} else {
			if err != nil {
				t.Errorf("ParseCRIUVersion(%q) unexpected error: %v", tc.input, err)
			} else if got != tc.want {
				t.Errorf("ParseCRIUVersion(%q) = %d, want %d", tc.input, got, tc.want)
			}
		}
	}
}

func TestCheckContainerdCRIUReadiness_DisabledByConfig(t *testing.T) {
	ctx := context.Background()
	nd := &Node{
		readConfigFileFn: func(path string) ([]byte, error) {
			return []byte("enable_criu = false\n"), nil
		},
		containerdConfigPath: "/etc/containerd/config.toml",
	}

	err := nd.CheckContainerdCRIUReadiness(ctx)
	if err == nil {
		t.Fatal("expected error when enable_criu = false, got nil")
	}
	if !strings.Contains(err.Error(), ReasonContainerdCRIUDisabled) {
		t.Fatalf("expected %q in error, got: %v", ReasonContainerdCRIUDisabled, err)
	}
	if !strings.Contains(err.Error(), RemediationContainerdCRIUDisabled) {
		t.Fatalf("expected %q in error, got: %v", RemediationContainerdCRIUDisabled, err)
	}
}

func TestCheckContainerdCRIUReadiness_CRIUMissingFromPATH(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	emptyBin := filepath.Join(tmpDir, "empty-bin")
	_ = os.MkdirAll(emptyBin, 0o755)

	nd := &Node{
		containerdConfigPath: "/dev/null", // empty config
		containerdPidFn: func() (int, error) {
			return 1234, nil
		},
		containerdEnvironFn: func(pid int) ([]byte, error) {
			return []byte(fmt.Sprintf("PATH=%s\x00", emptyBin)), nil
		},
	}

	err := nd.CheckContainerdCRIUReadiness(ctx)
	if err == nil {
		t.Fatal("expected error when criu is missing from PATH, got nil")
	}
	if !strings.Contains(err.Error(), ReasonCRIUNotOnContainerdPATH) {
		t.Fatalf("expected %q in error, got: %v", ReasonCRIUNotOnContainerdPATH, err)
	}
	if !strings.Contains(err.Error(), RemediationCRIUNotOnContainerdPATH) {
		t.Fatalf("expected %q in error, got: %v", RemediationCRIUNotOnContainerdPATH, err)
	}
}

func TestCheckContainerdCRIUReadiness_CRIUVersionTooOld(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	_ = os.MkdirAll(binDir, 0o755)
	criuBin := filepath.Join(binDir, "criu")
	_ = os.WriteFile(criuBin, []byte("#!/bin/sh\n"), 0o755)

	nd := &Node{
		containerdConfigPath: "/dev/null",
		containerdPidFn: func() (int, error) {
			return 1234, nil
		},
		containerdEnvironFn: func(pid int) ([]byte, error) {
			return []byte(fmt.Sprintf("PATH=%s\x00", binDir)), nil
		},
		criuVersionFn: func(ctx context.Context, path string) (int, error) {
			return 31500, nil // 3.15 is older than 3.16 (31600)
		},
	}

	err := nd.CheckContainerdCRIUReadiness(ctx)
	if err == nil {
		t.Fatal("expected error when CRIU version is too old, got nil")
	}
	if !strings.Contains(err.Error(), ReasonCRIUVersionTooOld) {
		t.Fatalf("expected %q in error, got: %v", ReasonCRIUVersionTooOld, err)
	}
	if !strings.Contains(err.Error(), RemediationUpgradeCRIU) {
		t.Fatalf("expected %q in error, got: %v", RemediationUpgradeCRIU, err)
	}
}

func TestCheckContainerdCRIUReadiness_SuccessViaShimPath(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	shimDir := filepath.Join(tmpDir, "shim-bin")
	_ = os.MkdirAll(shimDir, 0o755)
	criuBin := filepath.Join(shimDir, "criu")
	_ = os.WriteFile(criuBin, []byte("#!/bin/sh\n"), 0o755)

	nd := &Node{
		containerdConfigPath: "/dev/null",
		readConfigFileFn: func(path string) ([]byte, error) {
			return []byte(fmt.Sprintf("shim_path = %q\n", shimDir)), nil
		},
		criuVersionFn: func(ctx context.Context, path string) (int, error) {
			return 31900, nil
		},
	}

	if err := nd.CheckContainerdCRIUReadiness(ctx); err != nil {
		t.Fatalf("unexpected error on valid shim path: %v", err)
	}
}

func TestCheckContainerdCRIUReadiness_SuccessViaProcessPATH(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	_ = os.MkdirAll(binDir, 0o755)
	criuBin := filepath.Join(binDir, "criu")
	_ = os.WriteFile(criuBin, []byte("#!/bin/sh\n"), 0o755)

	nd := &Node{
		containerdConfigPath: "/dev/null",
		containerdPidFn: func() (int, error) {
			return 5678, nil
		},
		containerdEnvironFn: func(pid int) ([]byte, error) {
			return []byte(fmt.Sprintf("PATH=%s\x00", binDir)), nil
		},
		criuVersionFn: func(ctx context.Context, path string) (int, error) {
			return 31900, nil
		},
	}

	if err := nd.CheckContainerdCRIUReadiness(ctx); err != nil {
		t.Fatalf("unexpected error on valid process PATH: %v", err)
	}
}

func TestNode_BootstrapContainerdReadiness(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	nodeObj := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-readiness",
		},
		Status: corev1.NodeStatus{
			NodeInfo: corev1.NodeSystemInfo{
				ContainerRuntimeVersion: "containerd://2.3.4",
			},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(nodeObj).Build()

	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	_ = os.MkdirAll(binDir, 0o755)
	criuBin := filepath.Join(binDir, "criu")
	_ = os.WriteFile(criuBin, []byte("#!/bin/sh\n"), 0o755)

	enableCRIUVal := false
	nd := &Node{
		Client:   c,
		NodeName: "node-readiness",
		installBundleFn: func() (string, error) {
			return "v3.19", nil
		},
		readConfigFileFn: func(path string) ([]byte, error) {
			if !enableCRIUVal {
				return []byte("enable_criu = false\n"), nil
			}
			return []byte("enable_criu = true\n"), nil
		},
		containerdConfigPath: "/etc/containerd/config.toml",
		containerdPidFn: func() (int, error) {
			return 1000, nil
		},
		containerdEnvironFn: func(pid int) ([]byte, error) {
			return []byte(fmt.Sprintf("PATH=%s\x00", binDir)), nil
		},
		criuVersionFn: func(ctx context.Context, path string) (int, error) {
			return 31900, nil
		},
		Restorer: &restorer{
			execHost: func(ctx context.Context, env []string, name string, args ...string) (string, error) {
				return "Looks good", nil
			},
		},
	}

	// 1. Bootstrap fails when enable_criu = false
	err := nd.Bootstrap(ctx)
	if err == nil {
		t.Fatal("expected Bootstrap to fail when enable_criu = false, got nil")
	}
	if nd.IsReady() {
		t.Fatal("expected nd.IsReady() == false")
	}

	var cur corev1.Node
	if err := c.Get(ctx, types.NamespacedName{Name: "node-readiness"}, &cur); err != nil {
		t.Fatal(err)
	}
	if cur.Annotations[NodeAnnotationCRIUReady] != "false" {
		t.Fatalf("expected criu-ready=false, got %q", cur.Annotations[NodeAnnotationCRIUReady])
	}
	if cur.Annotations[NodeAnnotationCRIUReason] != ReasonContainerdCRIUDisabled {
		t.Fatalf("expected reason %q, got %q", ReasonContainerdCRIUDisabled, cur.Annotations[NodeAnnotationCRIUReason])
	}
	if cur.Annotations[NodeAnnotationCRIURemediation] != RemediationContainerdCRIUDisabled {
		t.Fatalf("expected remediation %q, got %q", RemediationContainerdCRIUDisabled, cur.Annotations[NodeAnnotationCRIURemediation])
	}

	// 2. Fix containerd config: enable_criu = true
	enableCRIUVal = true
	// Simulate containerd restart by updating socket inode
	nd.statSocketFn = func(path string) (uint64, error) {
		return 99999, nil
	}
	nd.SocketPath = "/run/containerd/containerd.sock"

	recovered, err := nd.ProbeReadiness(ctx)
	if err != nil {
		t.Fatalf("ProbeReadiness failed: %v", err)
	}
	if !recovered || !nd.IsReady() {
		t.Fatalf("expected node to recover readiness, got recovered=%v, isReady=%v", recovered, nd.IsReady())
	}

	if err := c.Get(ctx, types.NamespacedName{Name: "node-readiness"}, &cur); err != nil {
		t.Fatal(err)
	}
	if cur.Annotations[NodeAnnotationCRIUReady] != "true" {
		t.Fatalf("expected criu-ready=true after recovery, got %q", cur.Annotations[NodeAnnotationCRIUReady])
	}
	if _, ok := cur.Annotations[NodeAnnotationCRIUReason]; ok {
		t.Fatalf("expected reason annotation to be cleared, got %q", cur.Annotations[NodeAnnotationCRIUReason])
	}
	if _, ok := cur.Annotations[NodeAnnotationCRIURemediation]; ok {
		t.Fatalf("expected remediation annotation to be cleared, got %q", cur.Annotations[NodeAnnotationCRIURemediation])
	}
}

type conflictThenSucceedClient struct {
	client.Client
	conflictCount int32
	maxConflicts  int32
}

func (c *conflictThenSucceedClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	if atomic.AddInt32(&c.conflictCount, 1) <= c.maxConflicts {
		return apierrors.NewConflict(schema.GroupResource{Group: "", Resource: "nodes"}, obj.GetName(), errors.New("optimistic lock conflict"))
	}
	return c.Client.Patch(ctx, obj, patch, opts...)
}

func TestAnnotateNode_RetriesOnConflict(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	nodeObj := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-conflict",
		},
	}
	baseClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(nodeObj).Build()
	c := &conflictThenSucceedClient{
		Client:       baseClient,
		maxConflicts: 2,
	}

	// Should retry across the 2 conflicts and succeed on attempt 3
	err := annotateNode(ctx, c, c, "node-conflict", "v3.19", "", "", true)
	if err != nil {
		t.Fatalf("annotateNode failed despite retry: %v", err)
	}
	if c.conflictCount != 3 {
		t.Fatalf("expected 3 patch attempts (2 conflicts + 1 success), got %d", c.conflictCount)
	}

	var cur corev1.Node
	if err := baseClient.Get(ctx, types.NamespacedName{Name: "node-conflict"}, &cur); err != nil {
		t.Fatal(err)
	}
	if cur.Annotations[NodeAnnotationCRIUReady] != "true" {
		t.Fatalf("expected criu-ready=true, got %q", cur.Annotations[NodeAnnotationCRIUReady])
	}
}
