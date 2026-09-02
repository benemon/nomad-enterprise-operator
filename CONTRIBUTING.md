# Contributing to the Nomad Enterprise Operator

This is a community project. It is not affiliated with or supported by
HashiCorp. The operator manages Nomad Enterprise, and a Nomad Enterprise
license is required for the clusters it deploys.

Bugs and feature requests are welcome as GitHub issues. A good report
states what you deployed (CR spec), what you expected, and what the
operator did, including the relevant status conditions.

## Before designing anything

Ask *"what is the simplest machinery that enforces this contract?"* before
*"how do we design X?"*. At every decision, name the delete option: what
does this look like if we drop the component entirely? If the answer costs
a rare feature that carries its own lifecycle, deletion is usually right.

Every CRD field, function, and resource must justify its existence with a
current consumer, not a hypothetical one. Missing capability can be added
when someone needs it; speculative capability must be understood forever.

Two boundaries govern behaviour:

- **Follow Nomad's semantics, report accurately.** The operator mirrors
  what Nomad does. It does not block where Nomad does not block, does not
  invent lifecycle states Nomad lacks, and status must describe what is
  actually happening, not what a happy path assumes.
- **Security surfaces answer to the
  [threat model](docs/threat-model/README.md).** A change that moves
  secret material, widens RBAC, or adds an egress path updates that
  document in the same PR or explains why it does not need to.

The CRD surface is pre-1.0. Breaking spec changes are acceptable and ship
without migration machinery; they must be called out in the PR
description.

## Tests are the deliverable, not a follow-up

- Unit and envtest coverage includes negative cases.
- Behaviour with a runtime surface gets e2e coverage on kind, or an
  explicit written reason why not. Three classes are e2e-only signals,
  because envtest structurally cannot see them: status-write paths,
  log format, and status field renames.
- A guard (validation, RBAC aggregation, a CI gate) is done only when
  breaking it makes a named test fail.
- Verify effects, not statuses. A phase field saying `Succeeded` is a
  claim; the object listed in the bucket is evidence. Tests assert the
  latter wherever a real backend is in play.
- Cloud-backed specs are secret-gated and skip when credentials are
  absent. Every cloud lane creates per-run resources, deletes them on the
  way out, and sweeps stale leftovers on the way in. A lane that can leak
  billable resources is not done.

## Conventions

- Standard kubebuilder tooling: controller-gen, kustomize, envtest.
  Generated code is never hand-edited; `make manifests generate` must
  leave the tree clean.
- Comments are signposts, not exposition. One or two lines stating what
  the code cannot show.
- Match the conventions of the surrounding code and of sibling operators
  in the ecosystem, even where a style guide would suggest otherwise.
- Nomad agent configuration renders as HCL1. Unknown stanza names are
  silently ignored by Nomad's decoder, so config changes are proven
  against a live agent, not against the template.
- Docs prose uses plain hyphens and complete sentences, and states
  limitations up front.

## Gates

Before proposing a change:

```sh
make manifests generate fmt vet
make test lint
make test-e2e    # requires Kind; creates and tears down a cluster
```

CI additionally enforces grep checks (banned patterns), a CRD schema
snapshot (spec drift is a reviewed change, not an accident), and, on
release branches, an operand version-currency gate. A green local run is
the entry bar, not the finish line.

## Pull requests

- Branch from `main`; `main` is protected and takes changes only through
  PRs.
- One concern per PR. Describe the change on its own terms: what it does
  and why, including anything the diff cannot show, such as a contract
  quirk proven against a live system.
- If the PR changes documented behaviour, the docs change rides in the
  same PR.
