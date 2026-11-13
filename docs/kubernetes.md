# Kubernetes: `kubectl snoopy`

`kubectl snoopy` shows what a pod's containers send and receive over TLS,
the way snoopy shows a process's:

![kubectl snoopy on a deployment's two pods, decoded with --redact, then one line per call with --brief](kubectl-demo.gif)

A checkout deployment posting charges to a payments service in the
cluster, recorded with [demo/record-kubectl.sh](demo/record-kubectl.sh) on
[demo/kubectl-demo.yaml](demo/kubectl-demo.yaml).

```console
$ kubectl snoopy checkout-7d9f -n shop --brief
kubectl snoopy: starting snoopy on node pool-a-3, as pod shop/snoopy-checkout-7d9f-x2k4q, for pod checkout-7d9f
snoopy: attached to the openssl library (--verbose lists every file)
snoopy: tracing; press Ctrl-C to stop
09:14:02.118 checkout-7d9f/app node[4121] 10.0.3.17:41822 > 10.0.9.4:443 TLS 212: POST /v1/charge HTTP/1.1, host payments.internal
09:14:02.161 checkout-7d9f/app node[4121] 10.0.9.4:443 > 10.0.3.17:41822 TLS 98: HTTP/1.1 201 Created, application/json; body 54 bytes
```

## Installing

Each release has the plugin for Linux, macOS and Windows, and a krew
manifest, which krew can install from directly:

```bash
kubectl krew install --manifest-url=https://github.com/tks98/snoopy/releases/latest/download/krew-snoopy.yaml
```

Or download `kubectl-snoopy_<version>_<os>_<arch>.tar.gz` from the
[releases page](https://github.com/tks98/snoopy/releases) and put
`kubectl-snoopy` on your `PATH`; kubectl finds it there.

## Using it

```bash
kubectl snoopy POD                       # all of the pod's containers
kubectl snoopy POD -n shop -c app        # one container
kubectl snoopy deploy/checkout -n shop   # every pod of a deployment
kubectl snoopy deploy/checkout -n shop --status 5xx   # only failed responses
kubectl snoopy -l app=checkout -n shop   # every pod with these labels
kubectl snoopy POD --brief               # one line per call
kubectl snoopy POD --json --port 443     # JSON, port 443 only
kubectl snoopy deploy/checkout --java    # Java's own TLS too, through snoopy's agent
kubectl snoopy POD -- --max-size 65536   # any of snoopy's flags, after --
kubectl snoopy POD -- --quiet --har - > requests.har   # a HAR file, when you stop it (see below)
kubectl snoopy --cleanup                 # delete snoopy pods left behind
```

Besides a pod, it takes `KIND/NAME` for a deployment, statefulset, daemonset,
replicaset, job or service (`deploy/checkout`, `sts/db`, `svc/api`), or
`-l` with a label selector, and traces the pods those select. It runs one
snoopy pod per node, for all of the pods there, at most `--max-nodes` (10)
of them, and merges their output an event at a time, with their messages
marked by node.

It also follows them: pods that start later (a rollout, a scale-up) and
containers that restart (a crash loop, which gives them a new ID) are
traced as they come, by new snoopy pods, a node's together if they start
within a couple of seconds of each other, and a snoopy pod whose containers
are all gone is deleted. A new container's first calls can be missed while
its snoopy pod starts. `--no-follow` traces only what's running at the
start; with `--count`, which applies to each snoopy pod, it doesn't follow.

`--har -` and `--pcap -` write one snoopy's file to stdout, and two snoopy
pods' files one after the other would make neither readable. So with them
it doesn't follow, and it refuses pods on several nodes: trace one node's
at a time, or use `--json`, which merges.

`--brief`, `--json`, `--full`, `--hex`, `--verbose`, `--redact`, `--java`,
`--method`, `--path`, `--status`, `--host`, `--port` and `--count` are
snoopy's own and are passed on; the rest of snoopy's flags go
after `--` ([usage.md](usage.md) has them all). kubectl's usual flags
(`-n`, `--context`, `--kubeconfig`) work as they do for kubectl. Ctrl-C
stops it.

`--java` loads snoopy's Java agent into the JVMs in the pods' containers,
for Java's own TLS (SunJSSE), which isn't a library snoopy can probe
([how-it-works.md](how-it-works.md#java-and-jsse)). The JVMs need a
writable `/tmp`, which a pod with `readOnlyRootFilesystem` gets from an
`emptyDir` there. The agent stays in a JVM, idle, after you stop; a
container that restarts starts without it.

## What it does

1. It looks the pods up, and finds their nodes and their running
   containers' IDs.
2. It creates a pod on each of those nodes, in the target pod's namespace unless
   `--debug-namespace` says otherwise, from snoopy's image
   (`ghcr.io/tks98/snoopy`, the plugin's own version, or `--image`). Its
   container runs `snoopy --serve-exec`, which only waits. That pod is
   privileged and shares the node's PID namespace (`hostPID: true`), which
   snoopy needs to load its eBPF program and see the pod's processes,
   tolerates any taint, has no service account token, and may run for
   `--max-duration` (4 hours) at most.
3. It runs snoopy in those pods through `pods/exec`, as `kubectl exec`
   would, with `--container` for each of the containers there, so snoopy's
   output comes back on stdout and its messages on stderr.
4. When snoopy stops, or on Ctrl-C, it deletes them, and the waiting
   container passes the SIGTERM on to snoopy, which prints what it has
   left and its summary. `--keep` leaves them, with snoopy running, and
   `kubectl snoopy --cleanup` deletes the ones left behind (they're
   labeled `app.kubernetes.io/managed-by=kubectl-snoopy`).

### Where what it captures goes

Only to the plugin. A container's own output is its log: the kubelet keeps
it in a file on the node (`/var/log/pods/...`), log shippers send it on, and
anyone allowed `pods/log` in the namespace can read it. That's why snoopy
isn't the snoopy pod's container, which prints nothing, but runs through
exec, whose output the kubelet streams to the one who started it and keeps
nowhere. Nor does the pod's status get any of it: its termination message
is the container's own file, never the end of its log.

What's left: the plugin's own stdout, wherever you send it, and anyone who
can exec into the snoopy pod (`pods/exec` on it) can run snoopy too, or
whatever else, as anyone with that permission on a privileged pod can.

snoopy attaches its probes to the pod's processes only, so the node's other
pods don't pay for them (see [performance.md](performance.md)).

## What it needs

- **A namespace that allows privileged pods.** With Pod Security Admission,
  that's one whose `pod-security.kubernetes.io/enforce` level is
  `privileged` (or unset, on clusters without a default). If the target's
  namespace doesn't allow it, the plugin says so; run it with
  `--debug-namespace kube-system`, or a namespace made for it:

  ```bash
  kubectl create namespace snoopy
  kubectl label namespace snoopy pod-security.kubernetes.io/enforce=privileged
  kubectl snoopy POD -n shop --debug-namespace snoopy
  ```

- **Permission** to create, delete, watch and exec into pods in the snoopy
  pod's namespace, and to read pods, and the workloads it's given, in the
  target's:

  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: Role
  metadata: {name: snoopy, namespace: snoopy}   # the snoopy pods'
  rules:
    - apiGroups: [""]
      resources: [pods]
      verbs: [get, list, watch, create, delete]
    - apiGroups: [""]
      resources: [pods/exec]
      verbs: [create, get]   # SPDY takes create; WebSockets get, and create on newer API servers
    - apiGroups: [""]
      resources: [pods/log]
      verbs: [get]           # optional: to say why a snoopy pod ended (its log holds nothing captured)
  ---
  apiVersion: rbac.authorization.k8s.io/v1
  kind: Role
  metadata: {name: snoopy-targets, namespace: shop}   # the targets'
  rules:
    - apiGroups: [""]
      resources: [pods]
      verbs: [get, list, watch]   # list and watch for KIND/NAME, -l and following
    - apiGroups: [""]
      resources: [services]
      verbs: [get]
    - apiGroups: [apps]
      resources: [deployments, statefulsets, daemonsets, replicasets]
      verbs: [get]
    - apiGroups: [batch]
      resources: [jobs]
      verbs: [get]
  ```

  each bound with a RoleBinding (one Role does for both when they're the
  same namespace). `kubectl snoopy --cleanup` without `-n` lists and deletes
  snoopy pods in every namespace, which takes `list` and `delete` on pods in
  a ClusterRole; with `-n` it needs only the Role above. Anyone who can do
  this can read every pod's TLS traffic on the node, so it's for cluster
  admins.

- **Linux nodes, 5.10 or later**, x86-64 or arm64, ideally with BTF
  (`/sys/kernel/btf/vmlinux`; without it, socket addresses are looked up in
  `/proc` and can be missing). Windows nodes aren't supported.

- **The image**, from `ghcr.io/tks98/snoopy`. On clusters that can't pull
  from there, mirror it and pass `--image`.

kind, k3d and minikube (with the Docker driver) work too: their nodes are
containers with PID namespaces of their own, which snoopy numbers processes
by.

## Troubleshooting

- **"doesn't allow privileged pods":** see above; use `--debug-namespace`.
- **"snoopy's container can't start: ErrImagePull":** the node can't pull
  the image; mirror it and use `--image`. It says so as soon as the
  kubelet does.
- **"the image is older than this plugin":** its snoopy has no
  `--serve-exec`; use the image of the plugin's version (leave out
  `--image`), or mirror that one.
- **Nothing shows:** the pod's TLS may be in something snoopy doesn't trace
  (see [how-it-works.md](how-it-works.md); Java's own needs `--java`), or it
  made no calls while you watched. `-- --verbose` shows what snoopy attached to.
- **A snoopy pod was left behind** (the plugin was killed): `kubectl snoopy
  --cleanup`, or wait for `--max-duration`.

## Submitting to krew-index

Not done yet. When it is: the release's `krew-snoopy.yaml` is the manifest
for a PR adding `plugins/snoopy.yaml` to
[krew-index](https://github.com/kubernetes-sigs/krew-index), after checking
it with `kubectl krew install --manifest=krew-snoopy.yaml`. Once it's there,
the [krew-release-bot](https://github.com/rajatjindal/krew-release-bot)
action can open the index PR for each release. krew's naming guide prefers
descriptive names; if `snoopy` is questioned, `tls-snoop` is the fallback.
