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
	"reflect"
	"testing"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func runPDBPhase(t *testing.T, cluster *nomadv1alpha1.NomadCluster, seeds ...*policyv1.PodDisruptionBudget) (*policyv1.PodDisruptionBudget, bool) {
	t.Helper()

	builder := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(cluster)
	for _, seed := range seeds {
		builder = builder.WithRuntimeObjects(seed)
	}
	c := builder.Build()

	phaseCtx := &PhaseContext{
		Client: c,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}

	result := NewPDBPhase(phaseCtx).Execute(context.Background(), cluster)
	if result.Error != nil {
		t.Fatalf("Execute() error = %v, message = %s", result.Error, result.Message)
	}

	pdb := &policyv1.PodDisruptionBudget{}
	err := c.Get(context.Background(), types.NamespacedName{
		Name: cluster.Name, Namespace: cluster.Namespace,
	}, pdb)
	if errors.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("Get(PDB) error = %v", err)
	}
	return pdb, true
}

// TestPDBShape covers AC-2.3.1 — the PDB shape across the enum of
// supported replica counts. N=1 must produce no PDB; N=3/5 must
// produce a PDB with maxUnavailable=N/2 and a selector that matches
// the operator's pod labels.
//
// The phase logic is deterministic from spec.replicas and uses
// standard client-go primitives, so a fake client is sufficient
// here — the existing phase tests in this package
// (acl_bootstrap_test.go, cluster_status_test.go) follow the same
// pattern. AC-2.3.2 / AC-2.3.3 are exercised in dedicated tests
// below using the same approach.
func TestPDBShape(t *testing.T) {
	type tc struct {
		name              string
		replicas          int32
		wantPDB           bool
		wantMaxUnavail    int32
		wantSeedPDBExists bool // start with a PDB already in the cluster
	}
	cases := []tc{
		{name: "N=1 produces no PDB", replicas: 1, wantPDB: false},
		{name: "N=3 produces PDB with maxUnavailable=1", replicas: 3, wantPDB: true, wantMaxUnavail: 1},
		{name: "N=5 produces PDB with maxUnavailable=2", replicas: 5, wantPDB: true, wantMaxUnavail: 2},
		{
			name:              "scale-down to N=1 deletes the existing PDB",
			replicas:          1,
			wantPDB:           false,
			wantSeedPDBExists: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cluster := newTestCluster("test-ns", "test-cluster")
			cluster.Spec.Replicas = c.replicas

			var seeds []*policyv1.PodDisruptionBudget
			if c.wantSeedPDBExists {
				existing := intstr.FromInt32(1)
				seeds = append(seeds, &policyv1.PodDisruptionBudget{
					ObjectMeta: metav1.ObjectMeta{
						Name:      cluster.Name,
						Namespace: cluster.Namespace,
					},
					Spec: policyv1.PodDisruptionBudgetSpec{
						MaxUnavailable: &existing,
						Selector: &metav1.LabelSelector{
							MatchLabels: GetSelectorLabels(cluster),
						},
					},
				})
			}

			pdb, exists := runPDBPhase(t, cluster, seeds...)

			if !c.wantPDB {
				if exists {
					t.Errorf("expected no PDB, got %+v", pdb)
				}
				return
			}

			if !exists {
				t.Fatalf("expected PDB for replicas=%d, got none", c.replicas)
			}
			if pdb.Spec.MaxUnavailable == nil {
				t.Fatal("PDB.Spec.MaxUnavailable is nil")
			}
			if got := pdb.Spec.MaxUnavailable.IntVal; got != c.wantMaxUnavail {
				t.Errorf("MaxUnavailable = %d, want %d", got, c.wantMaxUnavail)
			}
			wantSelector := GetSelectorLabels(cluster)
			var gotSelector map[string]string
			if pdb.Spec.Selector != nil {
				gotSelector = pdb.Spec.Selector.MatchLabels
			}
			if !reflect.DeepEqual(gotSelector, wantSelector) {
				t.Errorf("Selector.MatchLabels = %v, want %v", gotSelector, wantSelector)
			}
			if len(pdb.OwnerReferences) == 0 {
				t.Error("PDB should have an owner reference to the NomadCluster")
			} else if pdb.OwnerReferences[0].Name != cluster.Name {
				t.Errorf("OwnerReference name = %q, want %q",
					pdb.OwnerReferences[0].Name, cluster.Name)
			}
		})
	}
}

// TestPDB_RecreatedOnDeletion covers AC-2.3.2 — when the PDB is
// removed out-of-band, the next reconcile recreates it with the
// expected shape. With the fake client we simulate the out-of-band
// delete by running Execute twice with a Delete between them.
func TestPDB_RecreatedOnDeletion(t *testing.T) {
	cluster := newTestCluster("test-ns", "test-cluster")
	cluster.Spec.Replicas = 3

	c := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(cluster).
		Build()

	phaseCtx := &PhaseContext{
		Client: c,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}
	phase := NewPDBPhase(phaseCtx)

	if res := phase.Execute(context.Background(), cluster); res.Error != nil {
		t.Fatalf("first Execute() error = %v", res.Error)
	}

	// Out-of-band delete
	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{Name: cluster.Name, Namespace: cluster.Namespace},
	}
	if err := c.Delete(context.Background(), pdb); err != nil {
		t.Fatalf("manual Delete(PDB) error = %v", err)
	}

	if res := phase.Execute(context.Background(), cluster); res.Error != nil {
		t.Fatalf("second Execute() error = %v", res.Error)
	}

	got := &policyv1.PodDisruptionBudget{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: cluster.Name, Namespace: cluster.Namespace,
	}, got); err != nil {
		t.Fatalf("PDB should be recreated after out-of-band deletion: %v", err)
	}
	if got.Spec.MaxUnavailable == nil || got.Spec.MaxUnavailable.IntVal != 1 {
		t.Errorf("recreated PDB MaxUnavailable = %v, want 1", got.Spec.MaxUnavailable)
	}
}

// TestPDB_UpdatedOnScale covers AC-2.3.3 — scale from N=3 to N=5
// updates the PDB's maxUnavailable from 1 to 2 within one reconcile.
func TestPDB_UpdatedOnScale(t *testing.T) {
	cluster := newTestCluster("test-ns", "test-cluster")
	cluster.Spec.Replicas = 3

	c := fake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithRuntimeObjects(cluster).
		Build()

	phaseCtx := &PhaseContext{
		Client: c,
		Scheme: scheme.Scheme,
		Log:    zap.New(zap.UseDevMode(true)),
	}
	phase := NewPDBPhase(phaseCtx)

	if res := phase.Execute(context.Background(), cluster); res.Error != nil {
		t.Fatalf("Execute() at N=3 error = %v", res.Error)
	}

	cluster.Spec.Replicas = 5
	if res := phase.Execute(context.Background(), cluster); res.Error != nil {
		t.Fatalf("Execute() at N=5 error = %v", res.Error)
	}

	got := &policyv1.PodDisruptionBudget{}
	if err := c.Get(context.Background(), types.NamespacedName{
		Name: cluster.Name, Namespace: cluster.Namespace,
	}, got); err != nil {
		t.Fatalf("Get(PDB) error = %v", err)
	}
	if got.Spec.MaxUnavailable == nil || got.Spec.MaxUnavailable.IntVal != 2 {
		t.Errorf("MaxUnavailable after scale = %v, want 2", got.Spec.MaxUnavailable)
	}
}
