package main

import (
	"context"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// runner runs the snoopy pods of one kubectl snoopy: one per node to start
// with, and with following, one for each node's new containers as they
// come, deleted when the containers it traces are gone.
type runner struct {
	o                 *options
	cfg               *rest.Config
	cs                kubernetes.Interface
	ns, debugNS       string
	image, name, what string
	args              []string
	multi             bool // several streams, merged
	out, errOut       *merger
	wg                sync.WaitGroup
	mu                sync.Mutex
	sessions          []*session
	failed            int                 // snoopy pods that failed, said so as they did
	stopping          bool                // removeAll has been called: no more snoopy pods
	owner             map[string]*session // a container ID's snoopy pod
	podOf             map[string]string   // a container ID's pod
	maxSessions       int
	// launch, if set, stands in for start for following's new containers:
	// a seam for tests, which have no API server to exec in.
	launch func(ctx context.Context, n nodeTargets) error
}

// track records the containers a snoopy pod traces. It returns false if
// the runner is stopping, when the pod is to be deleted instead.
func (r *runner) track(s *session, tgts []target) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions = append(r.sessions, s)
	for _, t := range tgts {
		pod, _, _ := strings.Cut(t.name, "/")
		s.ids[t.id] = true
		r.owner[t.id] = s
		r.podOf[t.id] = pod
	}
	return !r.stopping
}

// start creates a snoopy pod for the containers on a node, and runs snoopy
// in it in the background.
func (r *runner) start(ctx context.Context, n nodeTargets) error {
	spec := snoopyPod(n.node, r.name, r.ns+"/"+r.what, r.debugNS, r.image, r.o.deadline)
	created, err := r.cs.CoreV1().Pods(r.debugNS).Create(ctx, spec, metav1.CreateOptions{})
	if err != nil {
		return explainCreate(err, r.debugNS)
	}
	s := &session{o: r.o, node: n.node, ns: r.debugNS, name: created.Name, command: execCommand(n.targets, r.args), ids: map[string]bool{}}
	if !r.track(s, n.targets) {
		// Stopped while it was being created.
		s.remove(r.cs)
		return nil
	}
	r.o.logf("starting snoopy on node %s, as pod %s/%s, for %s", n.node, r.debugNS, created.Name, plural(n.pods))

	r.wg.Go(func() {
		stdout, stderr := io.Writer(r.o.streams.Out), io.Writer(r.o.streams.ErrOut)
		var flush []interface{ Flush() error }
		if r.multi {
			so := r.out.stream()
			se := &prefixWriter{m: r.errOut, prefix: []byte("[" + n.node + "] ")}
			stdout, stderr, flush = so, se, []interface{ Flush() error }{so, se}
		}
		err := s.run(ctx, r.cfg, r.cs, stdout, stderr)
		for _, f := range flush {
			_ = f.Flush()
		}
		if err != nil {
			// Now, not when everything's done: following can go on for long.
			r.o.logf("%v", err)
			r.mu.Lock()
			r.failed++
			r.mu.Unlock()
		}
		// Its container waits until deleted, snoopy or not.
		s.remove(r.cs)
	})
	return nil
}

// removeAll deletes every snoopy pod, all at once, and any started after.
func (r *runner) removeAll() {
	r.mu.Lock()
	r.stopping = true
	sessions := append([]*session(nil), r.sessions...)
	r.mu.Unlock()
	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Go(func() { s.remove(r.cs) })
	}
	wg.Wait()
}

// follow watches the target's pods until stop is closed, or ctx ends, and
// traces their containers that weren't, new pods' and restarted ones', with
// new snoopy pods, a node's together if they come within settle of each
// other. A snoopy pod whose containers have all gone is deleted. The snoopy
// pods run until ctx ends (or they're deleted), not until stop.
func (r *runner) follow(ctx context.Context, stop <-chan struct{}, opts metav1.ListOptions, settle time.Duration) {
	pending := map[string]*nodeTargets{}
	var timer <-chan time.Time
	// seen takes in a pod as it is now, or that it's gone.
	seen := func(pod *corev1.Pod, gone bool) {
		running := map[string]bool{}
		if !gone && pod.DeletionTimestamp == nil && pod.Status.Phase == corev1.PodRunning {
			if tgts, err := targets(pod, r.o.containers); err == nil {
				for _, t := range tgts {
					running[t.id] = true
					if r.covers(t.id) || isPending(pending, t.id) {
						continue
					}
					n := pending[pod.Spec.NodeName]
					if n == nil {
						n = &nodeTargets{node: pod.Spec.NodeName}
						pending[pod.Spec.NodeName] = n
					}
					if !slices.Contains(n.pods, pod.Name) {
						n.pods = append(n.pods, pod.Name)
					}
					n.targets = append(n.targets, t)
					if timer == nil {
						timer = time.After(settle)
					}
				}
			}
		}
		// Those that went while waiting to settle aren't started for.
		unpend(pending, pod.Name, running)
		r.gone(pod.Name, running)
	}

	stopped := func() bool {
		select {
		case <-stop:
			return true
		default:
			return ctx.Err() != nil
		}
	}
	for !stopped() {
		// A list, then a watch from it: pods that went while there was no
		// watch (when one ends, they do now and then), and so have no
		// Deleted event, are missing from the next list.
		list, err := r.cs.CoreV1().Pods(r.ns).List(ctx, opts)
		if err != nil {
			if ctx.Err() == nil {
				r.o.logf("can't follow new pods: %v", explainAPI(err))
			}
			return
		}
		listed := map[string]bool{}
		for i := range list.Items {
			listed[list.Items[i].Name] = true
			seen(&list.Items[i], false)
		}
		for _, pod := range r.tracedPods() {
			if !listed[pod] {
				seen(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod}}, true)
			}
		}
		var unlisted []string
		for _, n := range pending {
			for _, pod := range n.pods {
				if !listed[pod] {
					unlisted = append(unlisted, pod)
				}
			}
		}
		for _, pod := range unlisted {
			unpend(pending, pod, nil)
		}
		wopts := opts
		wopts.ResourceVersion = list.ResourceVersion
		w, err := r.cs.CoreV1().Pods(r.ns).Watch(ctx, wopts)
		if err != nil {
			if ctx.Err() == nil {
				r.o.logf("can't follow new pods: %v", explainAPI(err))
			}
			return
		}
		began := time.Now()
	events:
		for {
			select {
			case <-ctx.Done():
				w.Stop()
				return
			case <-stop:
				w.Stop()
				return
			case <-timer:
				timer = nil
				for node, n := range pending {
					if err := r.startNew(ctx, *n); err != nil {
						r.o.logf("can't trace new pods on node %s: %v", node, err)
					}
					delete(pending, node)
				}
			case ev, ok := <-w.ResultChan():
				if !ok || ev.Type == watch.Error {
					break events // a watch that ended, or is too old to go on: list again
				}
				pod, ok := ev.Object.(*corev1.Pod)
				if !ok || ev.Type == watch.Bookmark {
					continue
				}
				seen(pod, ev.Type == watch.Deleted)
			}
		}
		w.Stop()
		if time.Since(began) < time.Second {
			// Not a list a moment, should the watches end at once.
			select {
			case <-time.After(time.Second):
			case <-stop:
			case <-ctx.Done():
			}
		}
	}
}

// isPending reports whether a container is waiting to be traced.
func isPending(pending map[string]*nodeTargets, id string) bool {
	for _, n := range pending {
		if slices.ContainsFunc(n.targets, func(t target) bool { return t.id == id }) {
			return true
		}
	}
	return false
}

// unpend drops a pod's containers that aren't in running from those
// waiting to be traced.
func unpend(pending map[string]*nodeTargets, pod string, running map[string]bool) {
	for node, n := range pending {
		n.targets = slices.DeleteFunc(n.targets, func(t target) bool {
			p, _, _ := strings.Cut(t.name, "/")
			return p == pod && !running[t.id]
		})
		n.pods = slices.DeleteFunc(n.pods, func(p string) bool {
			return !slices.ContainsFunc(n.targets, func(t target) bool { return strings.HasPrefix(t.name, p+"/") })
		})
		if len(n.targets) == 0 {
			delete(pending, node)
		}
	}
}

// tracedPods returns the pods with containers that snoopy pods trace.
func (r *runner) tracedPods() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var pods []string
	for _, p := range r.podOf {
		if !slices.Contains(pods, p) {
			pods = append(pods, p)
		}
	}
	return pods
}

func (r *runner) covers(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.owner[id] != nil
}

func (r *runner) startNew(ctx context.Context, n nodeTargets) error {
	r.mu.Lock()
	full := len(r.liveLocked()) >= r.maxSessions
	r.mu.Unlock()
	if full {
		r.o.logf("not tracing %s on node %s: %d snoopy pods are running already (--max-nodes)", plural(n.pods), n.node, r.maxSessions)
		return nil
	}
	if r.launch != nil {
		return r.launch(ctx, n)
	}
	return r.start(ctx, n)
}

func (r *runner) liveLocked() []*session {
	var live []*session
	for _, s := range r.sessions {
		if !s.stopped() {
			live = append(live, s)
		}
	}
	return live
}

// gone notes that of pod's containers, only those in running are left, and
// deletes snoopy pods with nothing left to trace.
func (r *runner) gone(pod string, running map[string]bool) {
	r.mu.Lock()
	var empty []*session
	for id, p := range r.podOf {
		if p != pod || running[id] {
			continue
		}
		s := r.owner[id]
		delete(r.podOf, id)
		if s == nil {
			continue
		}
		delete(s.ids, id)
		if len(s.ids) == 0 {
			empty = append(empty, s)
		}
	}
	r.mu.Unlock()
	for _, s := range empty {
		if !s.stopped() {
			r.o.logf("the containers snoopy pod %s/%s traced are gone; deleting it", s.ns, s.name)
			s.remove(r.cs)
		}
	}
}

// watchOptions selects the pods a target names, for following them.
func watchOptions(ctx context.Context, cs kubernetes.Interface, ns, target, selector string) (metav1.ListOptions, error) {
	switch {
	case selector != "":
		return metav1.ListOptions{LabelSelector: selector}, nil
	case !strings.Contains(target, "/"):
		return metav1.ListOptions{FieldSelector: fields.OneTermEqualSelector("metadata.name", target).String()}, nil
	}
	kind, name, _ := strings.Cut(target, "/")
	k := kinds[strings.ToLower(kind)]
	if k == "pod" {
		return metav1.ListOptions{FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String()}, nil
	}
	sel, err := selectorOf(ctx, cs, ns, k, name)
	return metav1.ListOptions{LabelSelector: sel}, err
}
