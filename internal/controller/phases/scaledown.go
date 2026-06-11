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
	"fmt"
	"strconv"
	"strings"
	"time"

	nomadv1alpha1 "github.com/hashicorp/nomad-enterprise-operator/api/v1alpha1"
	"github.com/hashicorp/nomad-enterprise-operator/internal/metrics"
	"github.com/hashicorp/nomad-enterprise-operator/pkg/nomad"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ScaleDownPhase implements the Raft-aware scale-down loop (D2 / D2b
// neo-1ve.2). The flow per reconcile when sts.spec.replicas exceeds
// cluster.spec.replicas:
//
//  1. Initialise status.scaleDown if not yet present.
//  2. List Raft peers from Nomad; map each to a server ordinal.
//  3. Pick the highest-ordinal peer that is (a) above the desired
//     replica count and (b) not already recorded in
//     status.scaleDown.removedPeers.
//  4. Call RaftRemovePeer; verify the peer is gone by re-listing.
//  5. Append the server ID to status.scaleDown.removedPeers and
//     requeue immediately to remove the next peer.
//  6. When len(removedPeers) covers the full gap, patch
//     sts.spec.replicas to cluster.spec.replicas and clear
//     status.scaleDown in the same reconcile.
//
// Leader-loss handling (AC-2.3.8 / 2.3.8a) is intentionally minimal
// here — any Nomad-API error is logged at V(1) and the phase returns
// OK so the next reconcile retries. D2d (neo-1ve.4) refines this with
// explicit ScaleDownBlocked condition handling and silent-pause
// semantics on mid-operation leader loss. The metric
// nomad_operator_scale_down_in_progress (AC-8.1.6) is wired in D2e.
//
// PVC preservation (AC-2.3.4c): this phase never touches PVCs.
// reclaimPolicy governs cluster-delete only; the StatefulSet
// controller does not garbage-collect PVCs on replica reduction.
type ScaleDownPhase struct {
	*PhaseContext
}

// NewScaleDownPhase creates a new ScaleDownPhase.
func NewScaleDownPhase(ctx *PhaseContext) *ScaleDownPhase {
	return &ScaleDownPhase{PhaseContext: ctx}
}

// Name returns the phase name.
func (p *ScaleDownPhase) Name() string {
	return "ScaleDown"
}

// Execute runs one reconcile pass of the scale-down loop. Returns
// immediate requeue when there is more work to do; OK when the
// operation completed or there is no operation in flight.
func (p *ScaleDownPhase) Execute(ctx context.Context, cluster *nomadv1alpha1.NomadCluster) PhaseResult {
	sts := &appsv1.StatefulSet{}
	err := p.Client.Get(ctx, types.NamespacedName{
		Name:      cluster.Name,
		Namespace: cluster.Namespace,
	}, sts)
	if errors.IsNotFound(err) {
		// First reconcile — StatefulSet not created yet; nothing to scale down.
		return OK()
	}
	if err != nil {
		return Error(err, "Failed to get StatefulSet for scale-down")
	}

	if sts.Spec.Replicas == nil {
		// Defensive: a STS without replicas defaults to 1 on the apiserver
		// side, but treating that as "no scale-down" is the safest call here.
		return OK()
	}
	currentReplicas := *sts.Spec.Replicas
	desiredReplicas := cluster.Spec.Replicas

	if currentReplicas <= desiredReplicas {
		// No gap to close. If a prior operation left status.scaleDown
		// populated (e.g. the operator was killed between patching the
		// STS and clearing status), clear it now.
		if cluster.Status.ScaleDown != nil {
			patchBase := cluster.DeepCopy()
			cluster.Status.ScaleDown = nil
			if err := p.Client.Status().Patch(ctx, cluster, client.MergeFrom(patchBase)); err != nil {
				return Error(err, "Failed to clear status.scaleDown")
			}
		}
		// D2e (neo-1ve.5): no operation in flight.
		metrics.ScaleDownInProgress.WithLabelValues(cluster.Name, cluster.Namespace).Set(0)
		return OK()
	}

	// Gap > 0 — we owe the user a scale-down.
	gap := currentReplicas - desiredReplicas
	p.Log.Info("ScaleDown: gap detected", "from", currentReplicas, "to", desiredReplicas, "gap", gap)

	// D2e (neo-1ve.5): operation in flight. Set unconditionally on
	// every gap-detected reconcile so an operator pod restart inherits
	// the correct gauge value on its first reconcile (the in-process
	// metric is lost on restart; status.scaleDown is the durable
	// source of truth).
	metrics.ScaleDownInProgress.WithLabelValues(cluster.Name, cluster.Namespace).Set(1)

	token, err := p.getManagementToken(ctx, cluster)
	if err != nil {
		p.Log.Info("ScaleDown: deferring — management token not yet available", "error", err)
		return OK()
	}

	nomadClient, err := p.newNomadClientForScaleDown(cluster, token)
	if err != nil {
		p.Log.Info("ScaleDown: deferring — failed to construct Nomad client", "error", err)
		return OK()
	}

	// Pre-start gates: leader available, and (if scaling below 3) the
	// user has opted in to degraded quorum via annotation. Both are
	// only checked once per operation, before status.scaleDown is
	// initialised; the gates surface via the Ready condition so the
	// user sees what is blocking progress.
	if cluster.Status.ScaleDown == nil {
		// AC-2.3.8 (D2d / neo-1ve.4): leader probe.
		leader, lerr := nomadClient.GetLeader()
		if lerr != nil || leader == "" {
			p.Log.Info("ScaleDown: blocked — no Raft leader; deferring",
				"leader", leader, "error", lerr)
			return RequeueWithReason(15*time.Second, "ScaleDownBlocked",
				"Scale-down blocked: no Raft leader available")
		}

		// AC-2.3.5 / 2.3.6 (D2c / neo-1ve.3): degraded-quorum opt-in.
		// Required when transitioning from >= 3 down to < 3 (clusters
		// already below the floor are exempt — same shape the design
		// doc's CEL rule had). Enforced operator-side because CRD CEL
		// on K8s 1.36 cannot access metadata.annotations.
		if desiredReplicas < 3 && currentReplicas >= 3 && !hasAcceptDegradedQuorumAnnotation(cluster) {
			p.Log.Info("ScaleDown: blocked — degraded-quorum opt-in missing; deferring",
				"target", desiredReplicas, "annotation", acceptDegradedQuorumAnnotation)
			return RequeueWithReason(15*time.Second, "DegradedQuorumNotAccepted",
				"Scale-down below 3 replicas requires annotation "+
					acceptDegradedQuorumAnnotation+"=true")
		}

		patchBase := cluster.DeepCopy()
		cluster.Status.ScaleDown = &nomadv1alpha1.ScaleDownStatus{RemovedPeers: []string{}}
		if err := p.Client.Status().Patch(ctx, cluster, client.MergeFrom(patchBase)); err != nil {
			return Error(err, "Failed to initialise status.scaleDown")
		}
	}

	// If every peer in the gap is already recorded, finalise.
	if int32(len(cluster.Status.ScaleDown.RemovedPeers)) >= gap {
		return p.finalize(ctx, cluster, sts, desiredReplicas)
	}

	peers, err := nomadClient.RaftListPeers(ctx, token)
	if err != nil {
		// AC-2.3.8a: on mid-op leader loss, pause silently — status is
		// preserved, the next reconcile will retry and resume per
		// AC-2.3.7's resume logic. Other transient errors get the same
		// treatment (OK + log) so the reconciler keeps moving.
		if isNoLeaderError(err) {
			p.Log.Info("ScaleDown: leader lost mid-operation; silently pausing (AC-2.3.8a)", "error", err)
		} else {
			p.Log.Info("ScaleDown: deferring — RaftListPeers failed", "error", err)
		}
		return OK()
	}
	peerNodes := make([]string, 0, len(peers))
	for _, peer := range peers {
		peerNodes = append(peerNodes, peer.Node)
	}
	p.Log.Info("ScaleDown: peer list from Nomad", "nodes", peerNodes)

	candidate, err := p.pickNextPeer(cluster, peers, desiredReplicas)
	if err != nil {
		return Error(err, "Failed to pick next peer for removal")
	}
	if candidate == nil {
		p.Log.Info("ScaleDown: deferring — no peer matches the scale-down target this cycle")
		return OK()
	}

	p.Log.Info("Removing Raft peer",
		"id", candidate.ID, "address", candidate.Address,
		"removedSoFar", len(cluster.Status.ScaleDown.RemovedPeers), "gap", gap)

	if err := nomadClient.RaftRemovePeer(ctx, token, candidate.ID); err != nil {
		// AC-2.3.8a: leader loss between the list and the remove is a
		// transient Raft election. Pause silently — status.scaleDown
		// is not cleared, the next reconcile resumes per AC-2.3.7.
		if isNoLeaderError(err) {
			p.Log.Info("ScaleDown: leader lost during RaftRemovePeer; silently pausing (AC-2.3.8a)",
				"error", err, "id", candidate.ID)
		} else {
			p.Log.Info("ScaleDown: RaftRemovePeer failed (will retry)", "error", err, "id", candidate.ID)
		}
		return OK()
	}

	// Verify the peer is actually gone before recording it. A claimed
	// success without confirmation could let the loop double-remove on
	// resume.
	after, err := nomadClient.RaftListPeers(ctx, token)
	if err != nil {
		p.Log.V(1).Info("Failed to re-list peers after removal (will retry)", "error", err)
		return OK()
	}
	for _, peer := range after {
		if peer.ID == candidate.ID {
			p.Log.Info("Peer still present after RaftRemovePeer; not recording (will retry)",
				"id", candidate.ID)
			return OK()
		}
	}

	patchBase := cluster.DeepCopy()
	cluster.Status.ScaleDown.RemovedPeers = append(cluster.Status.ScaleDown.RemovedPeers, candidate.ID)
	if err := p.Client.Status().Patch(ctx, cluster, client.MergeFrom(patchBase)); err != nil {
		return Error(err, "Failed to record removed peer in status")
	}

	// If this was the last peer to remove, finalise immediately so the
	// STS is patched and status cleared in the same reconcile.
	if int32(len(cluster.Status.ScaleDown.RemovedPeers)) >= gap {
		return p.finalize(ctx, cluster, sts, desiredReplicas)
	}

	// More peers to remove; ask the controller-runtime to come right back.
	return Requeue(time.Second, "scale-down peer removed; continuing")
}

// finalize patches sts.spec.replicas down to the desired count and
// clears status.scaleDown. Called once the recorded removal count
// covers the gap (AC-2.3.7 completion clause).
func (p *ScaleDownPhase) finalize(
	ctx context.Context,
	cluster *nomadv1alpha1.NomadCluster,
	sts *appsv1.StatefulSet,
	desiredReplicas int32,
) PhaseResult {
	if sts.Spec.Replicas == nil || *sts.Spec.Replicas != desiredReplicas {
		patchBase := sts.DeepCopy()
		sts.Spec.Replicas = &desiredReplicas
		if err := p.Client.Patch(ctx, sts, client.MergeFrom(patchBase)); err != nil {
			return Error(err, "Failed to patch sts.spec.replicas at scale-down completion")
		}
		p.Log.Info("Patched StatefulSet replicas at scale-down completion",
			"name", sts.Name, "replicas", desiredReplicas)
	}

	if cluster.Status.ScaleDown != nil {
		patchBase := cluster.DeepCopy()
		cluster.Status.ScaleDown = nil
		if err := p.Client.Status().Patch(ctx, cluster, client.MergeFrom(patchBase)); err != nil {
			return Error(err, "Failed to clear status.scaleDown at completion")
		}
	}
	// D2e (neo-1ve.5): operation complete.
	metrics.ScaleDownInProgress.WithLabelValues(cluster.Name, cluster.Namespace).Set(0)
	return OK()
}

// pickNextPeer returns the candidate to remove this reconcile pass.
// It picks the highest-ordinal peer that (a) maps to our cluster,
// (b) has ordinal >= desiredReplicas (so it's above the floor),
// and (c) is not already in status.scaleDown.removedPeers. Returns
// nil if no candidate qualifies.
func (p *ScaleDownPhase) pickNextPeer(
	cluster *nomadv1alpha1.NomadCluster,
	peers []*nomad.RaftPeer,
	desiredReplicas int32,
) (*nomad.RaftPeer, error) {
	alreadyRemoved := map[string]bool{}
	if cluster.Status.ScaleDown != nil {
		for _, id := range cluster.Status.ScaleDown.RemovedPeers {
			alreadyRemoved[id] = true
		}
	}

	var best *nomad.RaftPeer
	bestOrdinal := -1
	for _, peer := range peers {
		if alreadyRemoved[peer.ID] {
			continue
		}
		ordinal, err := nodeNameToOrdinal(peer.Node, cluster.Name)
		if err != nil {
			// Peer doesn't match this cluster — log at V(1) and skip.
			// This is expected when there are foreign peers in the
			// configuration (e.g. multi-cluster lab setups), and also
			// when a peer's Node is "(unknown)" because the Nomad
			// server has not yet populated its node name.
			p.Log.V(1).Info("Skipping peer that does not map to a cluster ordinal",
				"node", peer.Node, "address", peer.Address,
				"cluster", cluster.Name, "error", err)
			continue
		}
		if int32(ordinal) < desiredReplicas {
			continue
		}
		if ordinal > bestOrdinal {
			best = peer
			bestOrdinal = ordinal
		}
	}
	return best, nil
}

// getManagementToken returns a token with operator:write capability,
// needed for RaftRemovePeer. For now this is the bootstrap token —
// the operator-status policy is intentionally read-only and a
// dedicated long-lived management token is C4's job (neo-ikf).
// Returns the empty string with no error when ACLs are disabled.
func (p *ScaleDownPhase) getManagementToken(
	ctx context.Context,
	cluster *nomadv1alpha1.NomadCluster,
) (string, error) {
	if !cluster.Spec.Server.ACL.Enabled {
		return "", nil
	}
	secret := &corev1.Secret{}
	if err := p.Client.Get(ctx, types.NamespacedName{
		Name:      BootstrapSecretName(cluster.Name),
		Namespace: cluster.Namespace,
	}, secret); err != nil {
		return "", err
	}
	token := string(secret.Data["secret-id"])
	if token == "" {
		return "", fmt.Errorf("bootstrap secret %q has no secret-id", BootstrapSecretName(cluster.Name))
	}
	return token, nil
}

// newNomadClientForScaleDown builds a Nomad client targeted at the
// in-cluster Service. Address fallback to LoadBalancer (the pattern
// ClusterStatusPhase uses) is not added here because scale-down only
// runs from inside the cluster; if the internal Service is
// unreachable the phase defers anyway.
func (p *ScaleDownPhase) newNomadClientForScaleDown(
	cluster *nomadv1alpha1.NomadCluster,
	token string,
) (nomad.NomadAPI, error) {
	cfg := p.BuildClientConfig(cluster, 10*time.Second, token)
	cfg.Address = nomad.InternalServiceAddress(cluster.Name, cluster.Namespace, true)
	return p.NewNomadClient(cfg)
}

// nodeNameToOrdinal maps a Nomad server's node name to the
// StatefulSet pod ordinal it represents. Returns an error for any
// name the operator cannot positively identify as one of its own
// server pods — never silently treats unrecognised input as ordinal
// 0. This is the AC-2.3.4a contract.
//
// Why node name and not the autopilot Address field: the operator's
// HCL template (pkg/hcl/generator.go) sets advertise.rpc to the
// cluster's LoadBalancer IP, which is shared across all replicas, so
// the autopilot Address field cannot be used to distinguish peers.
// The Node field carries the pod hostname suffixed with the region
// (Nomad's convention), which is per-replica.
//
// Recognised input shapes:
//   - <cluster>-<integer>             (e.g. "scaledown-test-2")
//   - <cluster>-<integer>.<region>    (e.g. "scaledown-test-2.global" — Nomad's autopilot output)
//
// Rejected: empty, "(unknown)" (Nomad's not-yet-set sentinel), names
// whose prefix does not match the cluster, names with a non-integer
// ordinal segment.
// acceptDegradedQuorumAnnotation is the opt-in signal users set on
// the NomadCluster CR to authorise a scale-down below the 3-replica
// quorum floor (AC-2.3.5 / 2.3.6). Enforced by ScaleDownPhase because
// CRD CEL on K8s 1.36 cannot access metadata.annotations.
const acceptDegradedQuorumAnnotation = "nomad.hashicorp.com/accept-degraded-quorum"

// hasAcceptDegradedQuorumAnnotation returns true when the user has
// set the degraded-quorum opt-in annotation to "true" on the cluster.
func hasAcceptDegradedQuorumAnnotation(cluster *nomadv1alpha1.NomadCluster) bool {
	return cluster.Annotations[acceptDegradedQuorumAnnotation] == "true"
}

// isNoLeaderError reports whether err names a transient
// "no Raft leader" condition rather than a real failure. Nomad and
// the SDK surface this as several distinct strings depending on which
// endpoint the call hit; substring match is the minimum sufficient
// detection given the SDK does not export a typed sentinel.
//
// Used by AC-2.3.8a's silent-pause path. Conservative on purpose: a
// false negative (real error mis-classified) just logs a generic
// "deferring" message; a false positive (no-leader mis-classified as
// real error) is harmless because both branches return OK and retry.
func isNoLeaderError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, marker := range []string{
		"No cluster leader",
		"no cluster leader",
		"leader not found",
		"no leader",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

func nodeNameToOrdinal(nodeName, clusterName string) (int, error) {
	if nodeName == "" {
		return 0, fmt.Errorf("peer node name is empty")
	}
	if nodeName == "(unknown)" {
		return 0, fmt.Errorf("peer node name is %q (Nomad has not yet populated node name)", nodeName)
	}
	prefix := clusterName + "-"
	if !strings.HasPrefix(nodeName, prefix) {
		return 0, fmt.Errorf("peer node name %q does not match cluster %q", nodeName, clusterName)
	}
	ordinalSegment := nodeName[len(prefix):]
	// Strip the ".<region>" suffix Nomad appends in autopilot output.
	if dot := strings.Index(ordinalSegment, "."); dot >= 0 {
		ordinalSegment = ordinalSegment[:dot]
	}
	if ordinalSegment == "" {
		return 0, fmt.Errorf("peer node name %q has empty ordinal after cluster prefix", nodeName)
	}
	ordinal, err := strconv.Atoi(ordinalSegment)
	if err != nil {
		return 0, fmt.Errorf("peer node name %q ordinal %q is not an integer: %w", nodeName, ordinalSegment, err)
	}
	return ordinal, nil
}
