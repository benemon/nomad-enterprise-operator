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

package metrics

import (
	"errors"
	"testing"

	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeAPI implements only the methods this test drives; embedding the
// interface satisfies the rest (calling them would panic, which is the
// point — the decorator must delegate exactly).
type fakeAPI struct {
	nomad.NomadAPI
	leader    string
	leaderErr error
}

func (f *fakeAPI) GetLeader() (string, error) { return f.leader, f.leaderErr }

// TestInstrumentedNomadAPICounts covers D4b / AC-8.1.2: every call
// through the decorator increments nomad_operator_nomad_api_requests_total
// with the method name and a success/error outcome, and the inner
// result passes through untouched.
func TestInstrumentedNomadAPICounts(t *testing.T) {
	okBefore := testutil.ToFloat64(NomadAPIRequests.WithLabelValues("GetLeader", "success"))
	errBefore := testutil.ToFloat64(NomadAPIRequests.WithLabelValues("GetLeader", "error"))

	api := InstrumentNomadAPI(&fakeAPI{leader: "10.0.0.1:4647"})
	leader, err := api.GetLeader()
	if err != nil || leader != "10.0.0.1:4647" {
		t.Fatalf("GetLeader() = %q, %v — decorator must delegate", leader, err)
	}

	failing := InstrumentNomadAPI(&fakeAPI{leaderErr: errors.New("no leader")})
	if _, err := failing.GetLeader(); err == nil {
		t.Fatal("GetLeader() expected error passthrough")
	}

	okDelta := testutil.ToFloat64(NomadAPIRequests.WithLabelValues("GetLeader", "success")) - okBefore
	errDelta := testutil.ToFloat64(NomadAPIRequests.WithLabelValues("GetLeader", "error")) - errBefore
	if okDelta != 1 || errDelta != 1 {
		t.Errorf("counter deltas success=%v error=%v, want 1 and 1", okDelta, errDelta)
	}
}
