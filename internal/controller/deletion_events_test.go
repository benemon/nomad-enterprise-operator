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
	"context"
	"fmt"
	"strings"
	"testing"

	"k8s.io/utils/ptr"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// A deletion-path failure must surface as a Warning Event: conditions
// race finalizer removal, so Events are the only user-visible signal —
// the reclaim-spec postmortem was four blind CI rounds because an RBAC
// denial lived solely in operator logs.
func TestDeletionFailuresEmitEvents(t *testing.T) {
	testScheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(testScheme); err != nil {
		t.Fatal(err)
	}
	if err := nomadv1alpha1.AddToScheme(testScheme); err != nil {
		t.Fatal(err)
	}

	newCluster := func() *nomadv1alpha1.NomadCluster {
		c := &nomadv1alpha1.NomadCluster{
			ObjectMeta: metav1.ObjectMeta{
				Name: "del", Namespace: "del-ns",
				Finalizers: []string{nomadClusterFinalizer},
			},
		}
		c.Spec.Persistence.ReclaimPolicy = nomadv1alpha1.ReclaimPolicyDelete
		c.Spec.Server.ACL.Enabled = ptr.To(false)
		return c
	}

	cases := []struct {
		name       string
		denyKind   string // object kind whose Delete errors
		wantReason string
	}{
		{"statefulset delete denied", "StatefulSet", "StatefulSetDeleteFailed"},
		{"pvc delete denied", "PersistentVolumeClaim", "PVCCleanupFailed"},
		{"bootstrap secret delete denied", "Secret", "BootstrapSecretDeleteFailed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := newCluster()
			pvc := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{
				Name: "data-del-0", Namespace: "del-ns",
				Labels: map[string]string{
					"app.kubernetes.io/name":     "nomad",
					"app.kubernetes.io/instance": "del",
					"app":                        "nomad",
					"component":                  "server",
				},
			}}
			builder := fake.NewClientBuilder().WithScheme(testScheme).
				WithObjects(cluster, pvc).
				WithInterceptorFuncs(interceptor.Funcs{
					Delete: func(ctx context.Context, cl client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						kind := fmt.Sprintf("%T", obj)
						if strings.Contains(kind, tc.denyKind) {
							return fmt.Errorf("simulated %s delete denial", tc.denyKind)
						}
						return cl.Delete(ctx, obj, opts...)
					},
				})
			recorder := record.NewFakeRecorder(10)
			r := &NomadClusterReconciler{
				Client:   builder.Build(),
				Scheme:   testScheme,
				Recorder: recorder,
			}
			// The StatefulSet is absent for the pvc/secret cases so the
			// gate proceeds; present for the sts case.
			if tc.denyKind == "StatefulSet" {
				sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "del", Namespace: "del-ns"}}
				Expect := r.Create(context.Background(), sts)
				if Expect != nil {
					t.Fatal(Expect)
				}
			}

			// Mark deleting: the finalizer keeps the object alive with
			// a deletionTimestamp (the fake client refuses pre-seeded
			// timestamps).
			markCluster := cluster.DeepCopy()
			if derr := r.Delete(context.Background(), markCluster); derr != nil {
				t.Fatal(derr)
			}

			_, err := r.handleDeletion(context.Background(), cluster)
			if err == nil {
				t.Fatal("handleDeletion must propagate the failure")
			}
			select {
			case e := <-recorder.Events:
				if !strings.Contains(e, "Warning") || !strings.Contains(e, tc.wantReason) {
					t.Fatalf("event = %q, want Warning %s", e, tc.wantReason)
				}
			default:
				t.Fatalf("no event emitted for %s", tc.wantReason)
			}
		})
	}
}
