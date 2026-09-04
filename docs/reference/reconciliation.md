# Reconciliation phases

The NomadCluster controller reconciles through a sequential phase pipeline:

1. **ServiceAccount** - creates the Nomad server ServiceAccount
2. **RBAC** - creates Roles and RoleBindings
3. **Gossip** - generates or resolves the gossip encryption key
4. **Services** - creates headless and external Kubernetes Services
5. **Advertise** - resolves the external LoadBalancer address
6. **Certificate** - generates CA and issues server/client certificates (after Advertise so the LoadBalancer IP is in the cert SANs)
7. **Secrets** - assembles the Nomad configuration secrets
8. **Keyring** - reconciles the external-KMS keyring set: resolves per-entry credentials, manages Vault token lifecycles, and drives keyring migrations
9. **Config** - renders server.hcl into the `<cluster>-config` Secret (a Secret, not a ConfigMap: it carries the gossip key and inline keyring credentials)
10. **StatefulSet** - creates or updates the Nomad server StatefulSet
11. **PDB** - creates or updates the PodDisruptionBudget for `spec.replicas ≥ 3` (skipped for `replicas = 1`)
12. **ScaleDown** - removes Raft peers when `sts.spec.replicas` exceeds `spec.replicas`, one peer per reconcile, before patching the StatefulSet (see [Scaling down](../guides/scaling.md#scaling-down))
13. **Route** - creates OpenShift Route and resolves the admitted hostname (when enabled, gated on Route CRD availability)
14. **Monitoring** - creates ServiceMonitor and PrometheusRule (when enabled, gated on Prometheus Operator CRD availability)
15. **ACLBootstrap** - bootstraps ACLs and creates the operator status token (when ACLs enabled)
16. **ClusterStatus** - queries the Nomad API for leader, autopilot health, and license status


