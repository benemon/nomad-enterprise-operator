/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
)

// TestMaybeAdvanceLastReconcileTimeGate verifies AC-2.8.4:
// status.lastReconcileTime updates only when (a) any other status field
// changed this reconcile, OR (b) >= defaultRequeueInterval/2 has elapsed
// since the previous update.
func TestMaybeAdvanceLastReconcileTimeGate(t *testing.T) {
	heartbeat := defaultRequeueInterval / 2
	r := &NomadClusterReconciler{}

	// Shared baselines so snapshot.LRT and current.LRT are
	// byte-identical when the test case calls for "no LRT change".
	recent := timePtr(time.Now().Add(-1 * time.Second))
	stale := timePtr(time.Now().Add(-heartbeat - 1*time.Second))

	tests := []struct {
		name           string
		snapshot       nomadv1alpha1.NomadClusterStatus
		current        nomadv1alpha1.NomadClusterStatus
		expectAdvanced bool
	}{
		{
			name:           "no state change AND no heartbeat → preserve LRT",
			snapshot:       nomadv1alpha1.NomadClusterStatus{Phase: "Running", LastReconcileTime: recent},
			current:        nomadv1alpha1.NomadClusterStatus{Phase: "Running", LastReconcileTime: recent},
			expectAdvanced: false,
		},
		{
			name:           "state change → advance LRT",
			snapshot:       nomadv1alpha1.NomadClusterStatus{Phase: "Running", LastReconcileTime: recent},
			current:        nomadv1alpha1.NomadClusterStatus{Phase: "Failed", LastReconcileTime: recent},
			expectAdvanced: true,
		},
		{
			name:           "no state change BUT heartbeat threshold reached → advance LRT",
			snapshot:       nomadv1alpha1.NomadClusterStatus{Phase: "Running", LastReconcileTime: stale},
			current:        nomadv1alpha1.NomadClusterStatus{Phase: "Running", LastReconcileTime: stale},
			expectAdvanced: true,
		},
		{
			name:           "first reconcile (snapshot LRT nil) → advance LRT",
			snapshot:       nomadv1alpha1.NomadClusterStatus{Phase: "Pending", LastReconcileTime: nil},
			current:        nomadv1alpha1.NomadClusterStatus{Phase: "Pending", LastReconcileTime: nil},
			expectAdvanced: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cluster := &nomadv1alpha1.NomadCluster{Status: *tc.current.DeepCopy()}
			snapshot := tc.snapshot.DeepCopy()
			snapshotLRT := snapshot.LastReconcileTime

			before := time.Now()
			r.maybeAdvanceLastReconcileTime(cluster, snapshot)
			after := time.Now()

			if tc.expectAdvanced {
				if cluster.Status.LastReconcileTime == nil {
					t.Fatalf("expected LastReconcileTime to be advanced but it is nil")
				}
				t0 := cluster.Status.LastReconcileTime.Time
				if t0.Before(before) || t0.After(after.Add(time.Second)) {
					t.Errorf("LRT %s not in [%s, %s]", t0, before, after)
				}
			} else {
				if cluster.Status.LastReconcileTime == nil {
					t.Fatal("expected LRT preserved but got nil")
				}
				if snapshotLRT == nil || !cluster.Status.LastReconcileTime.Time.Equal(snapshotLRT.Time) {
					t.Errorf("expected LRT preserved at %v; got %v", snapshotLRT, cluster.Status.LastReconcileTime)
				}
			}
		})
	}
}

func timePtr(t time.Time) *metav1.Time {
	mt := metav1.NewTime(t)
	return &mt
}
