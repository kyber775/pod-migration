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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// ReasonContainerdCRIUDisabled indicates containerd explicitly disabled CRIU in configuration.
	ReasonContainerdCRIUDisabled = "containerd configuration has enable_criu = false"
	// RemediationContainerdCRIUDisabled directs operator to enable CRIU in containerd config.
	RemediationContainerdCRIUDisabled = "enable CRIU in containerd configuration (/etc/containerd/config.toml) and restart containerd"

	// ReasonCRIUNotOnContainerdPATH indicates containerd's search path cannot resolve an executable criu.
	ReasonCRIUNotOnContainerdPATH = "criu binary not found in containerd search path"
	// RemediationCRIUNotOnContainerdPATH directs operator to install wrapper on containerd PATH.
	RemediationCRIUNotOnContainerdPATH = "install criu wrapper into a directory on containerd's PATH or restart containerd after PATH update"

	// ReasonCRIUVersionTooOld indicates the installed CRIU binary does not meet containerd minimum version.
	ReasonCRIUVersionTooOld = "installed CRIU binary version is older than containerd minimum (>= 3.16)"
	// RemediationUpgradeCRIU directs operator to upgrade the installed CRIU binary.
	RemediationUpgradeCRIU = "upgrade installed CRIU binary to >= 3.16"

	// MinContainerdCRIUVersion is the minimum CRIU version required by containerd (utils.PodCriuVersion: 3.16.0).
	MinContainerdCRIUVersion = 31600
)

// ParseContainerdConfig extracts enable_criu and any custom shim PATH from containerd's config.toml.
// If enable_criu is not explicitly set, enableCRIU returns nil (containerd defaults to true).
func ParseContainerdConfig(data []byte) (enableCRIU *bool, shimPath string, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if key == "enable_criu" {
				if strings.EqualFold(val, "false") {
					f := false
					enableCRIU = &f
				} else if strings.EqualFold(val, "true") {
					t := true
					enableCRIU = &t
				}
			} else if key == "shim_path" {
				shimPath = strings.Trim(val, `"' `)
			}
		}
		if strings.Contains(line, "PATH=") {
			start := strings.Index(line, "PATH=") + 5
			end := strings.IndexAny(line[start:], `"',]`)
			if end != -1 {
				shimPath = line[start : start+end]
			} else {
				shimPath = strings.Trim(line[start:], `"' `)
			}
		}
	}
	return enableCRIU, shimPath, scanner.Err()
}

// ParseProcessEnviron scans null-separated environment bytes for PATH= and returns its value.
func ParseProcessEnviron(environ []byte) string {
	entries := bytes.Split(environ, []byte{0})
	for _, entry := range entries {
		if bytes.HasPrefix(entry, []byte("PATH=")) {
			return string(bytes.TrimPrefix(entry, []byte("PATH=")))
		}
	}
	return ""
}

// ResolveCRIUPath searches searchPath for an executable criu binary.
// Follows containerd's resolveCriuPath lookup rules.
func ResolveCRIUPath(searchPath string) string {
	for _, dir := range filepath.SplitList(searchPath) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, "criu")
		fi, err := os.Stat(p)
		if err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	return ""
}

// ParseCRIUVersion parses CRIU version strings (e.g. "Version: 3.19", "3.16.1", "Version: 4.0")
// into an integer representation (Major*10000 + Minor*100 + Patch) matching utils.PodCriuVersion.
func ParseCRIUVersion(output string) (int, error) {
	fields := strings.Fields(output)
	var verStr string
	for i, f := range fields {
		if strings.EqualFold(f, "version:") && i+1 < len(fields) {
			verStr = fields[i+1]
			break
		}
		if strings.HasPrefix(strings.ToLower(f), "v") && len(f) > 1 && f[1] >= '0' && f[1] <= '9' {
			verStr = f[1:]
			break
		}
	}
	if verStr == "" && len(fields) > 0 {
		verStr = fields[0]
	}
	verStr = strings.TrimPrefix(verStr, "v")
	if idx := strings.IndexAny(verStr, "-+~"); idx != -1 {
		verStr = verStr[:idx]
	}
	parts := strings.Split(verStr, ".")
	if len(parts) < 2 {
		return 0, fmt.Errorf("unrecognized criu version format: %q", output)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("parse criu major version from %q: %w", output, err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, fmt.Errorf("parse criu minor version from %q: %w", output, err)
	}
	patch := 0
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	return major*10000 + minor*100 + patch, nil
}

// CheckContainerdCRIUReadiness verifies that containerd has CRIU enabled in its configuration,
// that containerd's search path (custom shim path or process PATH) resolves an executable criu binary,
// and that the binary meets containerd's minimum version (#130).
func (n *Node) CheckContainerdCRIUReadiness(ctx context.Context) error {
	// 1. Check containerd config (enable_criu & shim_path)
	configPath := n.containerdConfigPath
	if configPath == "" {
		for _, p := range []string{"/etc/containerd/config.toml", "/proc/1/root/etc/containerd/config.toml"} {
			if _, err := os.Stat(p); err == nil {
				configPath = p
				break
			}
		}
	}

	var shimPath string
	if configPath != "" {
		cfgData, err := n.readContainerdConfigFile(configPath)
		if err == nil {
			enableCRIU, sp, perr := ParseContainerdConfig(cfgData)
			if perr == nil {
				if enableCRIU != nil && !*enableCRIU {
					return fmt.Errorf("%s: %s", ReasonContainerdCRIUDisabled, RemediationContainerdCRIUDisabled)
				}
				shimPath = sp
			}
		}
	}

	// 2. Determine containerd search path
	var searchPath string
	if shimPath != "" {
		searchPath = shimPath
	} else {
		pid, err := n.getContainerdPid()
		if err == nil && pid > 0 {
			if envData, err := n.getContainerdEnviron(pid); err == nil {
				searchPath = ParseProcessEnviron(envData)
			}
		}
		if searchPath == "" {
			searchPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
		}
	}

	// 3. Resolve criu in search path
	criuPath := ResolveCRIUPath(searchPath)
	if criuPath == "" {
		return fmt.Errorf("%s (searched: %s): %s", ReasonCRIUNotOnContainerdPATH, searchPath, RemediationCRIUNotOnContainerdPATH)
	}

	// 4. Verify CRIU version
	ver, err := n.getCRIUVersion(ctx, criuPath)
	if err == nil && ver < MinContainerdCRIUVersion {
		return fmt.Errorf("%s (found %d, want >= %d): %s", ReasonCRIUVersionTooOld, ver, MinContainerdCRIUVersion, RemediationUpgradeCRIU)
	}

	return nil
}

func (n *Node) readContainerdConfigFile(path string) ([]byte, error) {
	if n != nil && n.readConfigFileFn != nil {
		return n.readConfigFileFn(path)
	}
	return os.ReadFile(path)
}

func (n *Node) getContainerdPid() (int, error) {
	if n != nil && n.containerdPidFn != nil {
		return n.containerdPidFn()
	}
	for _, p := range []string{"/run/containerd/containerd.pid", "/run/containerd.pid", "/proc/1/root/run/containerd/containerd.pid"} {
		if data, err := os.ReadFile(p); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
				return pid, nil
			}
		}
	}
	entries, err := os.ReadDir("/proc")
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(e.Name())
			if err != nil || pid <= 0 {
				continue
			}
			comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
			if err == nil && strings.TrimSpace(string(comm)) == "containerd" {
				return pid, nil
			}
		}
	}
	return 0, errors.New("cannot locate containerd pid")
}

func (n *Node) getContainerdEnviron(pid int) ([]byte, error) {
	if n != nil && n.containerdEnvironFn != nil {
		return n.containerdEnvironFn(pid)
	}
	return os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
}

func (n *Node) getCRIUVersion(ctx context.Context, criuPath string) (int, error) {
	if n != nil && n.criuVersionFn != nil {
		return n.criuVersionFn(ctx, criuPath)
	}
	out, err := exec.CommandContext(ctx, criuPath, "--version").CombinedOutput()
	if err != nil {
		return 0, err
	}
	return ParseCRIUVersion(string(out))
}
