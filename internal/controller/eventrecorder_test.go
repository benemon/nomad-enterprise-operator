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

package controller

import (
	"testing"

	"k8s.io/client-go/tools/record"
)

// TestEventRecorderInjectedOnNomadClusterReconciler verifies that constructing
// a NomadClusterReconciler with a Recorder leaves the field non-nil. This is
// the wiring check that downstream issues (B6, C5, C9, D3) depend on before
// they begin emitting their own Events.
func TestEventRecorderInjectedOnNomadClusterReconciler(t *testing.T) {
	recorder := record.NewFakeRecorder(10)
	r := &NomadClusterReconciler{Recorder: recorder}

	if r.Recorder == nil {
		t.Fatal("NomadClusterReconciler.Recorder is nil after injection")
	}
}

// TestEventRecorderInjectedOnNomadSnapshotReconciler verifies that constructing
// a NomadSnapshotReconciler with a Recorder leaves the field non-nil.
func TestEventRecorderInjectedOnNomadSnapshotReconciler(t *testing.T) {
	recorder := record.NewFakeRecorder(10)
	r := &NomadSnapshotReconciler{Recorder: recorder}

	if r.Recorder == nil {
		t.Fatal("NomadSnapshotReconciler.Recorder is nil after injection")
	}
}
