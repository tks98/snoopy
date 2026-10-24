# Plan: `kubectl snoopy`

Status: built (#42, #43, #44), except the krew-index submission, which is
left for later; [kubernetes.md](kubernetes.md) has how to use it and how to
submit it. Decided: the snoopy pod goes in the target's namespace by
default. Found while building it: kind's nodes (and k3d's, and minikube's
with Docker) have PID namespaces of their own, so snoopy had to number PIDs
as its own namespace does (#43).

A kubectl plugin that shows a pod's TLS traffic the way snoopy shows a
process's, ending with it in the krew index:

```console
$ kubectl snoopy checkout-7d9f -n shop --brief
snoopy: tracing container app of shop/checkout-7d9f on node pool-a-3
09:14:02.118 node[4121] 10.0.3.17:41822 > 10.0.9.4:443 TLS 212: POST /v1/charge HTTP/1.1, host payments.internal
09:14:02.161 node[4121] 10.0.9.4:443 > 10.0.3.17:41822 TLS 98: HTTP/1.1 201 Created, application/json; body 54 bytes
```

## How it works

The plugin runs on the user's machine (macOS, Windows or Linux) and snoopy
on the node, so they're two programs:

1. `kubectl snoopy POD` looks the pod up, finds its node and its containers'
   IDs (`status.containerStatuses[].containerID`, e.g. `containerd://3f2a…`).
2. It creates a pod on that node (`nodeName`), from snoopy's image
   (`ghcr.io/tks98/snoopy`, the version matching the plugin's), with
   `hostPID: true`, a privileged container, tolerations for any taint, and
   `restartPolicy: Never`, running `snoopy --container <ID>` plus the flags
   given (`--brief`, `--json`, `--host`, ...).
3. It attaches to that pod, so snoopy's output and its messages come back as
   stdout and stderr, apart (pod logs would mix them), and Ctrl-C stops it.
4. On exit, or Ctrl-C, it deletes the pod. Pods it makes are labeled, have
   an `activeDeadlineSeconds`, so one left behind by a killed plugin goes
   away anyway, and `kubectl snoopy --cleanup` deletes any that remain.

This is how `kubectl debug node`, ksniff and kubectl-trace work, so it's a
pattern cluster admins know.

## What snoopy needs first

- **`--container` per process.** With `--comm` and `--pid`, probes now go on
  the selected processes only; `--container` still puts them on files, so
  every other pod on the node using the same libssl would pay about 3 µs a
  call while someone watches one pod. The selected processes are those whose
  cgroup names the container, which `procinfo` already reads.
- **Pod names in the output.** snoopy shows `comm[pid]`; with
  `--label shop/checkout-7d9f/app` (or similar), it would add the pod and
  container to each event, in text, `--brief` and JSON, so output from
  several pods can be told apart.

Both are useful outside Kubernetes too: `docker run ... ghcr.io/tks98/snoopy
--container <id>` gets the first.

## The plugin

- A separate Go module in this repo, `cmd/kubectl-snoopy`, using client-go,
  so snoopy's own module doesn't take on client-go's dependencies. Built by
  GoReleaser for linux, darwin and windows, amd64 and arm64, into
  `kubectl-snoopy_<version>_<os>_<arch>.tar.gz` archives with the LICENSE
  (krew requires it in the archive).
- Flags: `-n/--namespace`, `-c/--container` (default: all of the pod's),
  `--context` and `--kubeconfig` (the standard ones, from
  `genericclioptions`), `--image` (for mirrored registries), and
  `--debug-namespace` for where the snoopy pod goes. Everything after the
  pod, or after `--`, goes to snoopy.
- Later: `-l app=checkout` for several pods (one snoopy pod per node, given
  all the containers on it), and `deploy/checkout` like kubectl's own
  resource syntax.

## What can go wrong

- **Pod Security Admission.** A privileged, `hostPID` pod is only allowed in
  a namespace whose level is `privileged`. The default for
  `--debug-namespace` is the target's namespace (as ksniff does), which on a
  locked-down cluster won't allow it; the plugin should say so and suggest
  `--debug-namespace` for one that does (`kube-system`, or one made for it),
  not just pass on the API's error.
- **RBAC:** creating pods there, and `pods/attach`. The README should list
  the role a user needs.
- **Nodes snoopy can't run on:** kernels older than 5.10, or without BTF
  (then addresses come from `/proc`, as on any host), and Windows nodes.
  GKE's COS, Bottlerocket, Talos and the like do have BTF; they need checking.
- **Images it can't pull:** air-gapped clusters, hence `--image`.
- **The node's runtime:** container IDs look the same for containerd and
  CRI-O, and snoopy's container ID detection reads cgroups, which works for
  both, but each needs testing.

## Testing

- Unit tests for the pod spec and flag handling, with client-go's fake
  clientset.
- An end-to-end test in CI with kind: a cluster on the runner, a pod with
  curl calling an HTTPS server, `kubectl snoopy` on it, and a check that the
  request shows (`--quiet`-safe: only our own test traffic). kind nodes are
  containers on the runner's kernel, which is enough for eBPF.
- By hand, once: a managed cluster (GKE or EKS) and k3s.

## Releasing and krew

1. GoReleaser builds the plugin's archives alongside snoopy's.
2. A krew manifest template, `.krew.yaml`, in this repo, and a first PR to
   [krew-index](https://github.com/kubernetes-sigs/krew-index) adding
   `plugins/snoopy.yaml`, tested with `kubectl krew install --manifest`.
3. After that's merged, the krew-release-bot action opens the index PR for
   each new release by itself.

The name may be questioned: krew's naming guide prefers names that say what
the plugin does, and `snoopy` doesn't. There are tool names in the index
(`sniff`, `tree`, `neat`), so I'd ask for `snoopy`, with `tls-snoop` as the
fallback.

## Order

1. snoopy: `--container` per process, and pod labels in the output. One
   or two days.
2. The plugin, for one pod, with cleanup and the PSA message. Two or three
   days.
3. kind end-to-end test in CI, and releasing the plugin's archives. One day.
4. Testing on a managed cluster; README and usage docs. One day.
5. The krew-index PR, and krew-release-bot. Then waiting on review.
6. Later: several pods and `deploy/...`.

## Decided

- The snoopy pod goes in the target's namespace by default, and
  `--debug-namespace` elsewhere; the plugin explains a Pod Security
  rejection.
- The plugin runs the image of its own version, so their flags stay in
  step.
