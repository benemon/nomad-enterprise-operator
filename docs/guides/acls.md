# ACL configuration

Bootstrapping ACLs by hand ends with a root token sitting in your
terminal history. The operator runs the bootstrap itself the moment the
cluster is ready and seals the result into Secrets, so no human ever
holds the token in a shell.

ACLs are enabled by default (`server.acl.enabled: true`). When the first server pod reports ready, the operator bootstraps the ACL system and provisions **three tokens**, each in its own Secret:

| Secret | Capabilities | Used for |
|--------|--------------|----------|
| `<cluster>-acl-bootstrap` | full management (Nomad bootstrap token) | Minting the management token at bootstrap, and revoking the derived tokens/policies on cluster deletion. Nothing else - day-2 operations never use it. |
| `<cluster>-operator-management` | management-type token | All day-2 management writes: keeping the operator-owned ACL policies in their desired state, minting the status token, and Raft peer removal during scale-down. Management-type because Nomad has no ACL-write policy grammar - only management tokens can write ACL state. |
| `<cluster>-operator-status` | `operator:read`, `agent:read` | All day-2 read-only queries: autopilot health, license status, leader, agent-version probe. |

The principle is separation per concern: the bootstrap token is
effectively sealed after minting the management token; writes ride the
management token (dedicated, independently revocable and rotatable -
delete its Secret to force a re-mint); reads ride the least-privilege
status token. The operator also keeps the operator-owned
`<cluster>-operator-status` policy in its desired state on every
reconcile - manual edits to it are reverted. The management
credential has no policy: it is a management-type token, because Nomad
has no ACL-write policy grammar.

Anonymous requests are denied. The operator creates no anonymous
policy, so operand clusters keep Nomad's default deny-all posture for
tokenless requests, and the web UI (including access via the OpenShift
Route) requires a token login. Admins who want tokenless read
visibility can create their own `anonymous` policy - the operator
leaves it alone.

On cluster deletion, the finalizer revokes the management and status
tokens and deletes their policies from Nomad (authenticating with the
bootstrap token, whose Secret is deliberately deleted last - see
[Bootstrap token Secret lifecycle](../security.md#bootstrap-token-secret-lifecycle)).


