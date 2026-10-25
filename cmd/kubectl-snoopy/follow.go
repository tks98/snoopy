package main

import (
	"context"
	"io"
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
	errs              []error
	owner             map[string]*session // a container ID's snoopy pod
	podOf             map[string]string   // a container ID's pod
	maxSessions       int
	// launch starts a snoopy pod for new containers: start, or in tests, a
	// stand-in.
	launch func(ctx context.Context, n nodeTargets) error
}

// track records the containers a snoopy pod traces.
func (r *runner) track(s *session, tgts []target) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions = append(r.sessions, s)
	for _, t := range tgts {
		pod, _, _ := strings.Cut(t.name, "/")
		s.ids[t.id] = true
		r.owner[t.id] = s
		r.podOf[t.id] = pod
	}
}

// start creates a snoopy pod for the containers on a node, and streams its
// output in the background.
func (r *runner) start(ctx context.Context, n nodeTargets) error {
	spec := snoopyPod(n.node, r.name, r.ns+"/"+r.what, r.debugNS, r.image, snoopyArgs(n.targets, r.args), r.o.deadline)
	created, err := r.cs.CoreV1().Pods(r.debugNS).Create(ctx, spec, metav1.CreateOptions{})
	if err != nil {
		return explainCreate(err, r.debugNS)
	}
	s := &session{o: r.o, node: n.node, ns: r.debugNS, name: created.Name, ids: map[string]bool{}}
	r.track(s, n.targets)
	r.o.logf("starting snoopy on node %s, as pod %s/%s, for %s", n.node, r.debugNS, created.Name, plural(n.pods))

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
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
		r.mu.Lock()
		r.errs = append(r.errs, err)
		r.mu.Unlock()
	}()
	return nil
}

func (r *runner) removeAll() {
	r.mu.Lock()
	sessions := append([]*session(nil), r.sessions...)
	r.mu.Unlock()
	for _, s := range sessions {
		s.remove(r.cs)
	}
}

// follow watches the target's pods until ctx ends, and traces their
// containers that weren't, new pods' and restarted ones', with new snoopy
// pods, a node's together if they come within settle of each other. A
// snoopy pod whose containers have all gone is deleted.
func (r *runner) follow(ctx context.Context, opts metav1.ListOptions, settle time.Duration) {
	pending := map[string]*nodeTargets{}
	var timer <-chan time.Time
	for ctx.Err() == nil {
		w, err := r.cs.CoreV1().Pods(r.ns).Watch(ctx, opts)
		if err != nil {
			r.o.logf("can't follow new pods: %v", err)
			return
		}
	events:
		for {
			select {
			case <-ctx.Done():
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
				if !ok {
					break events // watches end now and then; start another
				}
				pod, ok := ev.Object.(*corev1.Pod)
				if !ok {
					continue
				}
				running := map[string]bool{}
				if ev.Type != watch.Deleted && pod.DeletionTimestamp == nil && pod.Status.Phase == corev1.PodRunning {
					if tgts, err := targets(pod, r.o.containers); err == nil {
						for _, t := range tgts {
							running[t.id] = true
							if r.covers(t.id) {
								continue
							}
							n := pending[pod.Spec.NodeName]
							if n == nil {
								n = &nodeTargets{node: pod.Spec.NodeName}
								pending[pod.Spec.NodeName] = n
							}
							if !strings.Contains(strings.Join(n.pods, " "), pod.Name) {
								n.pods = append(n.pods, pod.Name)
							}
							n.targets = append(n.targets, t)
							if timer == nil {
								timer = time.After(settle)
							}
						}
					}
				}
				r.gone(pod.Name, running)
			}
		}
		w.Stop()
	}
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
