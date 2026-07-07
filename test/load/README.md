# Operator load testing

The load-test rig is [kube-burner](https://kube-burner.github.io/kube-burner/latest/),
run via the **Load Test** GitHub Actions workflow (manual dispatch,
`tier` input). Configuration, a guided tour with upstream doc links,
and instructions for reading a run live in
[kube-burner/README.md](kube-burner/README.md).

To run the same rig against a real OpenShift cluster — for the larger
tiers the GHA runners can't hold, and to exercise SCCs and User
Workload Monitoring — see
[kube-burner/README-ocp.md](kube-burner/README-ocp.md).
