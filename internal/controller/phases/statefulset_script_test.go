/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package phases

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// Executes the rendered start command's self-heal block against fixture
// filesystems and a stubbed nslookup, asserting the guard fails closed:
// peers.json appears only for a positively-verified lone server. Runs
// the exact shipped script text with only path substitution and the
// final exec replaced.
func TestStartCommandSelfHealScript(t *testing.T) {
	phase := &StatefulSetPhase{PhaseContext: &PhaseContext{
		Client: fake.NewClientBuilder().WithScheme(scheme.Scheme).Build(),
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}}
	sts := phase.buildStatefulSet(context.Background(), newTestCluster("ns", "nomad"))
	script := sts.Spec.Template.Spec.Containers[0].Command[2]

	cases := []struct {
		name        string
		nslookup    string // stub stdout; empty = no output
		bootstrap   string
		nodeID      string
		podIP       string
		wantWrite   bool
		wantAddress string
	}{
		{"lone v4 server heals", "Name:\tnomad-headless.ns.svc.cluster.local\nAddress: 10.1.2.3\n",
			"  bootstrap_expect = 1", "abc-123", "10.1.2.3", true, `"address":"10.1.2.3:4647"`},
		{"empty lookup fails closed", "",
			"  bootstrap_expect = 1", "abc-123", "10.1.2.3", false, ""},
		{"v4 sibling blocks", "Name:\tx\nAddress: 10.1.2.3\nName:\tx\nAddress: 10.1.2.4\n",
			"  bootstrap_expect = 1", "abc-123", "10.1.2.3", false, ""},
		{"v6 sibling blocks", "Name:\tx\nAddress: 10.1.2.3\nName:\tx\nAddress: fd00::9\n",
			"  bootstrap_expect = 1", "abc-123", "10.1.2.3", false, ""},
		{"resolver address line not counted as sibling", "Server:\t10.96.0.10\nAddress: 10.96.0.10:53\n\nName:\tx\nAddress: 10.1.2.3\n",
			"  bootstrap_expect = 1", "abc-123", "10.1.2.3", true, `"address":"10.1.2.3:4647"`},
		{"multi-server config blocks", "Name:\tx\nAddress: 10.1.2.3\n",
			"  bootstrap_expect = 3", "abc-123", "10.1.2.3", false, ""},
		{"missing node-id blocks", "Name:\tx\nAddress: 10.1.2.3\n",
			"  bootstrap_expect = 1", "", "10.1.2.3", false, ""},
		{"empty POD_IP blocks", "Name:\tx\nAddress: 10.1.2.3\n",
			"  bootstrap_expect = 1", "abc-123", "", false, ""},
		{"lone v6 server heals with brackets", "Name:\tx\nAddress: fd00::3\n",
			"  bootstrap_expect = 1", "abc-123", "fd00::3", true, `"address":"[fd00::3]:4647"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dataDir := filepath.Join(root, "data", "server")
			raftDir := filepath.Join(dataDir, "raft")
			confDir := filepath.Join(root, "config")
			runtDir := filepath.Join(root, "config-runtime")
			binDir := filepath.Join(root, "bin")
			for _, d := range []string{raftDir, confDir, runtDir, binDir} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.nodeID != "" {
				if err := os.WriteFile(filepath.Join(dataDir, "node-id"), []byte(tc.nodeID), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(confDir, "server.hcl"),
				[]byte("server {\n"+tc.bootstrap+"\n}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			quoted := "'" + strings.ReplaceAll(tc.nslookup, "'", `'\''`) + "'"
			if err := os.WriteFile(filepath.Join(binDir, "nslookup"),
				[]byte("#!/bin/sh\nprintf '%s' "+quoted+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			// sleep stubbed to keep the fail-closed retry loop instant.
			if err := os.WriteFile(filepath.Join(binDir, "sleep"),
				[]byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}

			s := strings.ReplaceAll(script, "/nomad/data/server", dataDir)
			s = strings.ReplaceAll(s, "/nomad/config-runtime", runtDir)
			s = strings.ReplaceAll(s, "/nomad/config/", confDir+"/")
			s = strings.ReplaceAll(s, "exec nomad agent -config="+runtDir+"/server.hcl", "true")

			cmd := exec.Command("/bin/sh", "-ec", s)
			cmd.Env = append(os.Environ(),
				"PATH="+binDir+":"+os.Getenv("PATH"),
				"POD_IP="+tc.podIP,
				"POD_NAME=nomad-0",
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("script exited non-zero: %v\n%s", err, out)
			}

			peers, readErr := os.ReadFile(filepath.Join(raftDir, "peers.json"))
			if tc.wantWrite {
				if readErr != nil {
					t.Fatalf("peers.json missing, want write; script output:\n%s", out)
				}
				for _, want := range []string{`"id":"` + tc.nodeID + `"`, tc.wantAddress, `"non_voter":false`} {
					if !strings.Contains(string(peers), want) {
						t.Errorf("peers.json = %s, missing %q", peers, want)
					}
				}
			} else if readErr == nil {
				t.Fatalf("peers.json written when it must not be: %s\noutput:\n%s", peers, out)
			}
			if _, err := os.Stat(filepath.Join(raftDir, "peers.json.tmp")); err == nil {
				t.Error("temporary peers.json.tmp left behind")
			}
		})
	}
}
