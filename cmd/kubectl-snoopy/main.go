// Command kubectl-snoopy is a kubectl plugin that shows what a pod's
// containers send and receive over TLS. It runs snoopy on the pod's node,
// in a privileged pod of its own that shares the node's PID namespace,
// through pods/exec so snoopy's output comes back to it (and isn't the
// pod's log), and deletes the pod when done.
package main

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"
	"k8s.io/streaming/pkg/httpstream"
)

// version is set at build time with -ldflags "-X main.version=...", and
// picks snoopy's image: the same release.
var version = "dev"

const example = `  # What the pod's containers send and receive over TLS
  kubectl snoopy checkout-7d9f -n shop

  # One line per call, for one container
  kubectl snoopy checkout-7d9f -n shop -c app --brief

  # Every pod of a deployment, or with a label
  kubectl snoopy deploy/checkout -n shop --brief
  kubectl snoopy -l app=checkout -n shop --json

  # Java's own TLS (SunJSSE) too, through snoopy's agent in the JVMs
  kubectl snoopy deploy/checkout -n shop --java

  # JSON, only connections to port 443
  kubectl snoopy checkout-7d9f --json --port 443 | jq .

  # snoopy's other flags go after --
  kubectl snoopy checkout-7d9f -- --max-size 65536 --verbose

  # Delete snoopy pods left behind, in every namespace
  kubectl snoopy --cleanup`

const long = `Shows what a pod's containers send and receive over TLS, decoded, without
certificates or changes to the pod. It runs snoopy (https://github.com/tks98/snoopy)
on the pod's node, in a pod of its own, and deletes that pod when you stop it.
Given a deployment, statefulset, daemonset, replicaset, job or service
(KIND/NAME), or -l, it traces the pods they select, with one snoopy pod per
node. It follows them too: pods that start later, and containers that
restart, are traced as they come (--no-follow traces only those running when
it starts).

The snoopy pod is privileged and shares the node's PID namespace, which
snoopy needs for eBPF. Pod Security Admission allows that only in namespaces
whose level is privileged; by default it goes in the target pod's namespace,
and --debug-namespace puts it elsewhere. It needs permission to create and
delete pods there, and pods/exec: snoopy runs in the pod through exec, so
what it captures comes back to the plugin only, and not into the pod's log.

Its output contains whatever the pod sends, passwords and tokens included.`

type options struct {
	config     *genericclioptions.ConfigFlags
	streams    genericiooptions.IOStreams
	containers []string
	selector   string
	maxNodes   int
	debugNS    string
	image      string
	deadline   time.Duration
	keep       bool
	noFollow   bool
	cleanup    bool
	version    bool

	// snoopy's own flags, the commonest, passed on.
	brief, json, full, hex, verbose, redact, java bool
	hosts, ports                                  []string
	methods, paths, statuses                      []string
	count                                         int
}

func main() {
	o := &options{
		config:  genericclioptions.NewConfigFlags(true),
		streams: genericiooptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr},
	}
	if err := newCommand(o).Execute(); err != nil {
		if !errors.Is(err, errReported) {
			fmt.Fprintln(os.Stderr, "kubectl snoopy:", err)
		}
		os.Exit(1)
	}
}

func newCommand(o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:           "kubectl snoopy (POD | KIND/NAME | -l SELECTOR) [flags] [-- snoopy flags]",
		Short:         "Show what a pod sends and receives over TLS",
		Long:          long,
		Example:       example,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case o.version:
				fmt.Fprintln(o.streams.Out, "kubectl-snoopy", version)
				return nil
			case o.cleanup:
				return o.runCleanup(cmd.Context())
			}
			dash := cmd.ArgsLenAtDash()
			var rest []string
			if dash >= 0 {
				args, rest = args[:dash], args[dash:]
			}
			switch {
			case len(args) == 0 && o.selector != "":
				return o.run(cmd.Context(), "", rest)
			case len(args) != 1:
				return errors.New("give a pod, KIND/NAME (deploy/checkout) or -l SELECTOR (see --help)")
			}
			return o.run(cmd.Context(), args[0], rest)
		},
	}
	f := cmd.Flags()
	o.config.AddFlags(f)
	f.StringSliceVarP(&o.containers, "container", "c", nil, "only these containers of the pods (default: all of them)")
	f.StringVarP(&o.selector, "selector", "l", "", "the pods with these labels, instead of a pod or KIND/NAME")
	f.IntVar(&o.maxNodes, "max-nodes", 10, "the most nodes to run snoopy pods on")
	f.StringVar(&o.debugNS, "debug-namespace", "", "namespace for the snoopy pod (default: the target pod's)")
	f.StringVar(&o.image, "image", "", "snoopy's image (default: "+defaultImage+", this plugin's version)")
	f.DurationVar(&o.deadline, "max-duration", 4*time.Hour, "how long the snoopy pod may run, should the plugin be killed")
	f.BoolVar(&o.keep, "keep", false, "leave the snoopy pods, and snoopy running in them, when done (--cleanup deletes them)")
	f.BoolVar(&o.noFollow, "no-follow", false, "don't trace pods that start, or containers that restart, after it did")
	f.BoolVar(&o.cleanup, "cleanup", false, "delete snoopy pods left behind (in --namespace, or all)")
	f.BoolVar(&o.version, "version", false, "print the plugin's version")
	f.BoolVar(&o.brief, "brief", false, "snoopy: one line per call")
	f.BoolVar(&o.json, "json", false, "snoopy: one JSON object per call")
	f.BoolVar(&o.full, "full", false, "snoopy: whole bodies, and binary data as hex dumps")
	f.BoolVar(&o.hex, "hex", false, "snoopy: payloads as hex dumps")
	f.BoolVar(&o.verbose, "verbose", false, "snoopy: also calls that only keep connections going")
	f.BoolVar(&o.redact, "redact", false, "snoopy: mask credentials, secret fields and recognizable tokens")
	f.BoolVar(&o.java, "java", false, "snoopy: also Java's own TLS (SunJSSE), by loading snoopy's agent into the containers' JVMs")
	f.StringArrayVar(&o.hosts, "host", nil, "snoopy: only connections with this address, network or host at either end")
	f.StringArrayVar(&o.ports, "port", nil, "snoopy: only connections with this port at either end")
	f.StringArrayVar(&o.methods, "method", nil, "snoopy: only requests with this method, and their responses")
	f.StringArrayVar(&o.paths, "path", nil, "snoopy: only requests whose path starts with this, and their responses")
	f.StringArrayVar(&o.statuses, "status", nil, "snoopy: only responses with this status (404, 5xx, 400-499)")
	f.IntVar(&o.count, "count", 0, "snoopy: stop after N calls")
	return cmd
}

// passed returns snoopy's flags that were given to the plugin.
func (o *options) passed() []string {
	var args []string
	for flag, set := range map[string]bool{"--brief": o.brief, "--json": o.json, "--full": o.full, "--hex": o.hex, "--verbose": o.verbose, "--redact": o.redact, "--java": o.java} {
		if set {
			args = append(args, flag)
		}
	}
	slices.Sort(args)
	for _, h := range o.hosts {
		args = append(args, "--host", h)
	}
	for _, p := range o.ports {
		args = append(args, "--port", p)
	}
	for _, f := range []struct {
		flag string
		vs   []string
	}{{"--method", o.methods}, {"--path", o.paths}, {"--status", o.statuses}} {
		for _, v := range f.vs {
			args = append(args, f.flag, v)
		}
	}
	if o.count > 0 {
		args = append(args, "--count", fmt.Sprint(o.count))
	}
	return args
}

func (o *options) clients() (*rest.Config, kubernetes.Interface, string, error) {
	cfg, err := o.config.ToRESTConfig()
	if err != nil {
		return nil, nil, "", err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, "", err
	}
	ns, _, err := o.config.ToRawKubeConfigLoader().Namespace()
	return cfg, cs, ns, err
}

func (o *options) logf(format string, a ...any) {
	fmt.Fprintf(o.streams.ErrOut, "kubectl snoopy: "+format+"\n", a...)
}

func (o *options) run(ctx context.Context, target string, rest []string) error {
	cfg, cs, ns, err := o.clients()
	if err != nil {
		return explainAPI(err)
	}
	pods, what, err := resolvePods(ctx, cs, ns, target, o.selector)
	if err != nil {
		return explainAPI(err)
	}
	nodes, err := byNode(pods, o.containers, o.logf)
	if err != nil {
		return err
	}
	if len(nodes) > o.maxNodes {
		return fmt.Errorf("%s run on %d nodes, which would take a snoopy pod on each; --max-nodes %d allows it",
			what, len(nodes), len(nodes))
	}
	image := o.image
	if image == "" {
		image = defaultImage + ":" + strings.TrimPrefix(version, "v")
		if version == "dev" {
			image = defaultImage + ":latest"
		}
	}
	debugNS := o.debugNS
	if debugNS == "" {
		debugNS = ns
	}
	name := target
	if target == "" || strings.Contains(target, "/") {
		_, name, _ = strings.Cut(target, "/")
		name = cmp.Or(name, "selected")
	}
	args := append(o.passed(), rest...)
	// Following new pods, unless told not to, or --count makes each snoopy
	// pod stop by itself.
	follow := !o.noFollow && o.count == 0 && !slices.Contains(rest, "--count")
	// A HAR or pcap file on stdout is one snoopy's, whole: two would make
	// neither readable.
	if flag := fileToStdout(rest); flag != "" {
		if len(nodes) > 1 {
			return fmt.Errorf("%s run on %d nodes, which would take a snoopy pod on each, but %s - is one snoopy's file; "+
				"trace the pods of one node at a time (or write --json, which merges)", what, len(nodes), flag)
		}
		if follow {
			o.logf("not following new pods: %s - is one snoopy's file", flag)
			follow = false
		}
	}

	blocks := !o.brief && !o.json && !slices.Contains(rest, "--brief") && !slices.Contains(rest, "--json")
	r := &runner{o: o, cfg: cfg, cs: cs, ns: ns, debugNS: debugNS, image: image, name: name, what: what, args: args,
		multi: len(nodes) > 1 || follow, out: newMerger(o.streams.Out, blocks), errOut: newMerger(o.streams.ErrOut, false),
		owner: map[string]*session{}, podOf: map[string]string{}, maxSessions: o.maxNodes}

	// Ctrl-C stops following and deletes the snoopy pods, which stops
	// snoopy (SIGTERM): each prints what it has and its summary, and its
	// stream ends. A second one gives up. With --keep, nothing is deleted,
	// so the first gives up.
	stopped := make(chan os.Signal, 2)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopped)
	defer r.removeAll()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	followCtx, stopFollowing := context.WithCancel(ctx)
	defer stopFollowing()
	go func() {
		select {
		case <-stopped:
		case <-ctx.Done():
			return
		}
		stopFollowing()
		if o.keep {
			cancel()
			return
		}
		r.removeAll()
		select {
		case <-stopped:
			cancel()
		case <-ctx.Done():
		}
	}()

	// One snoopy pod per node, for the containers there, unless stopped
	// before they all are.
	for _, n := range nodes {
		if followCtx.Err() != nil {
			break
		}
		if err := r.start(ctx, n); err != nil {
			return err
		}
	}
	if follow && followCtx.Err() == nil {
		opts, err := watchOptions(ctx, cs, ns, target, o.selector)
		if err != nil {
			o.logf("can't follow new pods: %v", explainAPI(err))
		} else {
			o.logf("following %s: new pods, and restarted containers, are traced as they start (--no-follow not to)", what)
			r.follow(ctx, followCtx.Done(), opts, 2*time.Second)
		}
	}
	r.wg.Wait()
	if r.failed > 0 {
		return errReported
	}
	return nil
}

// errReported is returned when what went wrong has been said already.
var errReported = errors.New("failed")

// fileToStdout returns the flag among snoopy's arguments that writes a
// file to stdout (--har - or --pcap -), or "".
func fileToStdout(args []string) string {
	for i, a := range args {
		if a == "--" {
			break
		}
		flag, value, ok := strings.Cut(a, "=")
		if !ok && i+1 < len(args) {
			value = args[i+1]
		}
		if f := "--" + strings.TrimLeft(flag, "-"); (f == "--har" || f == "--pcap") && value == "-" {
			return f
		}
	}
	return ""
}

// explainAPI adds a hint to an error talking to the cluster, when it's one
// that says nothing of what to check.
func explainAPI(err error) error {
	var ue *url.Error
	switch {
	case clientcmd.IsEmptyConfig(err):
		return fmt.Errorf("no cluster to talk to: kubectl has no current context (see kubectl config get-contexts, --context and --kubeconfig)\n  %w", err)
	case errors.As(err, &ue):
		return fmt.Errorf("can't reach the cluster's API server; is kubectl's context the right one, and does kubectl get pods work?\n  %w", err)
	case apierrors.IsUnauthorized(err):
		return fmt.Errorf("the API server didn't accept kubectl's credentials; does kubectl get pods work?\n  %w", err)
	case apierrors.IsForbidden(err):
		return fmt.Errorf("not allowed (kubectl snoopy needs get, list and watch on pods; see its docs, docs/kubernetes.md)\n  %w", err)
	}
	return err
}

func plural(pods []string) string {
	if len(pods) == 1 {
		return "pod " + pods[0]
	}
	return fmt.Sprintf("%d pods", len(pods))
}

// session is one snoopy pod, and the snoopy run in it.
type session struct {
	o        *options
	node     string
	ns, name string
	command  []string        // snoopy's, run in the pod
	ids      map[string]bool // the containers it traces that are still there; guarded by the runner's mu
	mu       sync.Mutex
	deleted  bool
	removed  chan struct{} // closed once the pod's deletion has been asked for
}

// remove deletes the pod, and returns when it has been, whoever asked
// first: the plugin mustn't exit while a deletion is on its way.
func (s *session) remove(cs kubernetes.Interface) {
	s.mu.Lock()
	if s.o.keep {
		s.mu.Unlock()
		return
	}
	first := !s.deleted
	s.deleted = true
	if s.removed == nil {
		s.removed = make(chan struct{})
	}
	removed := s.removed
	s.mu.Unlock()
	if !first {
		<-removed
		return
	}
	defer close(removed)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := cs.CoreV1().Pods(s.ns).Delete(ctx, s.name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		s.o.logf("couldn't delete pod %s/%s: %v (kubectl snoopy --cleanup deletes it)", s.ns, s.name, err)
	}
}

func (s *session) stopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleted
}

// run waits for the pod, runs snoopy in it until snoopy ends, and returns
// an error if snoopy failed, or couldn't start, unless it was stopped.
func (s *session) run(ctx context.Context, cfg *rest.Config, cs kubernetes.Interface, stdout, stderr io.Writer) error {
	running, err := waitRunning(ctx, cs, s.ns, s.name)
	switch {
	case s.stopped() || ctx.Err() != nil:
		return nil
	case err != nil:
		return fmt.Errorf("node %s: %w", s.node, err)
	case !running:
		return s.ended(ctx, cs)
	}
	err = execSnoopy(ctx, cfg, cs, s.ns, s.name, s.command, stdout, stderr)
	var exit utilexec.ExitError
	switch {
	case s.stopped() || ctx.Err() != nil:
		return nil
	case errors.As(err, &exit):
		return fmt.Errorf("node %s: snoopy exited with status %d", s.node, exit.ExitStatus())
	case err != nil:
		if ended := s.ended(ctx, cs); ended != nil {
			return ended
		}
		if strings.Contains(err.Error(), "forbidden") {
			return fmt.Errorf("node %s: not allowed to run snoopy in pod %s/%s (it needs create and get on pods/exec)\n  %w", s.node, s.ns, s.name, err)
		}
		return fmt.Errorf("node %s: run snoopy in pod %s/%s: %w", s.node, s.ns, s.name, err)
	}
	return nil
}

// ended says why the snoopy pod stopped before snoopy could run in it, or
// returns nil if it hasn't. What its container said is in its log: that's
// only snoopy --serve-exec, never what snoopy captures, so it's shown.
func (s *session) ended(ctx context.Context, cs kubernetes.Interface) error {
	pod, err := cs.CoreV1().Pods(s.ns).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		return nil
	}
	why := ""
	for _, c := range pod.Status.ContainerStatuses {
		if t := c.State.Terminated; t != nil {
			why = fmt.Sprintf("its container exited with status %d (%s)", t.ExitCode, t.Reason)
		}
	}
	if why == "" {
		if pod.Status.Phase != corev1.PodFailed && pod.Status.Phase != corev1.PodSucceeded {
			return nil
		}
		why = strings.TrimSpace(fmt.Sprintf("it %s: %s %s", strings.ToLower(string(pod.Status.Phase)), pod.Status.Reason, pod.Status.Message))
	}
	limit := int64(4096)
	var log []byte
	if r, err := cs.CoreV1().Pods(s.ns).GetLogs(s.name, &corev1.PodLogOptions{Container: snoopyName, LimitBytes: &limit}).Stream(ctx); err == nil {
		log, _ = io.ReadAll(r)
		_ = r.Close()
	}
	if bytes.Contains(log, []byte("serve-exec")) {
		return fmt.Errorf("node %s: the image is older than this plugin (it has no snoopy --serve-exec); use the plugin's own (leave out --image), or one as new", s.node)
	}
	if text := strings.TrimSpace(string(log)); text != "" {
		why += ":\n  " + strings.ReplaceAll(text, "\n", "\n  ")
	}
	return fmt.Errorf("node %s: the snoopy pod %s/%s ended before snoopy could run in it; %s", s.node, s.ns, s.name, why)
}

// waitRunning waits for the snoopy pod to run, and reports whether it does,
// or has already ended.
func waitRunning(ctx context.Context, cs kubernetes.Interface, ns, name string) (bool, error) {
	w, err := cs.CoreV1().Pods(ns).Watch(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String(),
	})
	if err != nil {
		return false, err
	}
	defer w.Stop()
	for ev := range w.ResultChan() {
		pod, ok := ev.Object.(*corev1.Pod)
		if !ok {
			continue
		}
		if ev.Type == watch.Deleted {
			return false, errors.New("the snoopy pod was deleted before it started")
		}
		switch pod.Status.Phase {
		case corev1.PodRunning:
			return true, nil
		case corev1.PodSucceeded, corev1.PodFailed:
			return false, nil
		}
		if p := waitingProblem(pod); p != "" {
			return false, fmt.Errorf("snoopy's container can't start: %s", p)
		}
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	return false, errors.New("stopped watching the snoopy pod before it started")
}

// execSnoopy runs command in the snoopy pod's container, and streams its
// stdout and stderr, apart, as kubectl exec does: over WebSockets, or SPDY
// on older API servers.
func execSnoopy(ctx context.Context, cfg *rest.Config, cs kubernetes.Interface, ns, name string, command []string, stdout, stderr io.Writer) error {
	req := cs.CoreV1().RESTClient().Post().Resource("pods").Namespace(ns).Name(name).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{Container: snoopyName, Command: command, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	spdy, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return err
	}
	ws, err := remotecommand.NewWebSocketExecutor(cfg, "GET", req.URL().String())
	if err != nil {
		return err
	}
	exec, err := remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	if err != nil {
		return err
	}
	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: stdout, Stderr: stderr})
}

// runCleanup deletes the snoopy pods this plugin made, in --namespace if it
// was given, or in every namespace.
func (o *options) runCleanup(ctx context.Context) error {
	_, cs, _, err := o.clients()
	if err != nil {
		return explainAPI(err)
	}
	ns := ""
	if o.config.Namespace != nil && *o.config.Namespace != "" {
		ns = *o.config.Namespace
	}
	return explainAPI(cleanup(ctx, cs, ns, o.streams.ErrOut))
}

func cleanup(ctx context.Context, cs kubernetes.Interface, ns string, w io.Writer) error {
	pods, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: managedByLabel + "=" + managedBy})
	if err != nil {
		return err
	}
	if len(pods.Items) == 0 {
		fmt.Fprintln(w, "kubectl snoopy: no snoopy pods to delete")
	}
	var errs []error
	for _, p := range pods.Items {
		if err := cs.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{}); err != nil {
			errs = append(errs, err)
			continue
		}
		fmt.Fprintf(w, "kubectl snoopy: deleted %s/%s (for %s)\n", p.Namespace, p.Name, p.Annotations[targetKey])
	}
	return errors.Join(errs...)
}
