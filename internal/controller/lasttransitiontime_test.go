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
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestSetStatusConditionPreservesTransitionTimeOnSteadyState verifies the
// invariant A1 depends on: meta.SetStatusCondition leaves LastTransitionTime
// unchanged when called repeatedly with the same Status/Reason. This is the
// reason the explicit `LastTransitionTime: metav1.Now()` was removed from
// every call site (the helper handles it).
//
// AC-2.8.2 partial coverage: a fully controller-driven steady-state test
// (asserting zero Status().Update calls on no-op reconcile) requires the
// mockable NomadAPI from F1; that broader test will land as part of F1.
func TestSetStatusConditionPreservesTransitionTimeOnSteadyState(t *testing.T) {
	conditions := []metav1.Condition{}

	original := metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionTrue,
		Reason:  "ClusterReady",
		Message: "all replicas ready",
	}
	meta.SetStatusCondition(&conditions, original)
	if len(conditions) != 1 {
		t.Fatalf("expected 1 condition after first set, got %d", len(conditions))
	}
	firstLTT := conditions[0].LastTransitionTime
	if firstLTT.IsZero() {
		t.Fatal("LastTransitionTime should be populated by SetStatusCondition")
	}

	// Sleep so any unintended Now() rewrite would produce a measurably
	// different timestamp.
	time.Sleep(50 * time.Millisecond) // real wall-clock gap: LastTransitionTime has second granularity; deliberate (neo-9eq)

	// Same condition again — no status change.
	meta.SetStatusCondition(&conditions, metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionTrue,
		Reason:  "ClusterReady",
		Message: "all replicas ready",
	})
	if len(conditions) != 1 {
		t.Fatalf("expected 1 condition after second set, got %d", len(conditions))
	}
	if !conditions[0].LastTransitionTime.Equal(&firstLTT) {
		t.Errorf("LastTransitionTime mutated on steady state: original=%s now=%s — the helper should only update transition time when Status/Reason changes; if this test fails after a code change, the controller is re-introducing the LastTransitionTime: metav1.Now() anti-pattern",
			firstLTT, conditions[0].LastTransitionTime)
	}
}

// TestSetStatusConditionUpdatesTransitionTimeOnRealTransition is the negative
// case: when the condition's Status genuinely changes, LastTransitionTime
// MUST advance.
func TestSetStatusConditionUpdatesTransitionTimeOnRealTransition(t *testing.T) {
	conditions := []metav1.Condition{}

	meta.SetStatusCondition(&conditions, metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionFalse,
		Reason:  "WaitingForReplicas",
		Message: "0/3",
	})
	firstLTT := conditions[0].LastTransitionTime

	time.Sleep(50 * time.Millisecond) // real wall-clock gap: LastTransitionTime has second granularity; deliberate (neo-9eq)

	// Genuine transition: False → True.
	meta.SetStatusCondition(&conditions, metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionTrue,
		Reason:  "ClusterReady",
		Message: "3/3",
	})
	if conditions[0].LastTransitionTime.Equal(&firstLTT) {
		t.Error("LastTransitionTime should have advanced on a Status transition")
	}
}
