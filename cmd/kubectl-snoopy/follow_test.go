package main

import (
	"context"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// Following: a pod traced from the start isn't traced again; a new pod, and
// a restarted container (a new ID), get snoopy pods; the snoopy pod of
// containers that are gone is deleted.
func TestFollow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := shopPod("checkout-a", "node-1", "checkout", corev1.PodRunning)
	cs := fake.NewClientset(first)
	streams, _, _, _ := genericiooptions.NewTestIOStreams()
	o := &options{streams: streams}
	var mu sync.Mutex
	var launched []nodeTargets
	r := &runner{o: o, cs: cs, ns: "shop", debugNS: "shop", owner: map[string]*session{}, podOf: map[string]string{}, maxSessions: 10}
	r.launch = func(_ context.Context, n nodeTargets) error {
		mu.Lock()
		launched = append(launched, n)
		mu.Unlock()
		r.track(&session{o: o, node: n.node, ns: "shop", name: "snoopy-" + n.pods[0], ids: map[string]bool{}}, n.targets)
		return nil
	}
	// As at the start: checkout-a is traced.
	tgts, _ := targets(first, nil)
	firstSession := &session{o: o, node: "node-1", ns: "shop", name: "snoopy-start", ids: map[string]bool{}}
	r.track(firstSession, tgts)

	go r.follow(ctx, nil, metav1.ListOptions{}, 20*time.Millisecond)
	waitFor := func(n int, what string) []nodeTargets {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			mu.Lock()
			got := append([]nodeTargets(nil), launched...)
			mu.Unlock()
			if len(got) >= n {
				return got
			}
		}
		t.Fatalf("%s: %d snoopy pods launched, want %d", what, len(launched), n)
		return nil
	}
	time.Sleep(100 * time.Millisecond)
	if len(launched) != 0 {
		t.Fatalf("the pod traced from the start was launched for again: %+v", launched)
	}

	// A new pod.
	if _, err := cs.CoreV1().Pods("shop").Create(ctx, shopPod("checkout-b", "node-2", "checkout", corev1.PodRunning), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	got := waitFor(1, "new pod")
	if got[0].node != "node-2" || got[0].pods[0] != "checkout-b" || got[0].targets[0].id != "containerd://checkout-b" {
		t.Errorf("new pod: %+v", got[0])
	}

	// checkout-a's container restarts, with a new ID: traced anew, and the
	// snoopy pod of the old one is deleted.
	restarted := first.DeepCopy()
	restarted.Status.ContainerStatuses[0].ContainerID = "containerd://checkout-a-2"
	if _, err := cs.CoreV1().Pods("shop").Update(ctx, restarted, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	got = waitFor(2, "restarted container")
	if got[1].targets[0].id != "containerd://checkout-a-2" {
		t.Errorf("restart: %+v", got[1])
	}
	if !firstSession.stopped() {
		t.Error("the snoopy pod of the restarted container's old ID wasn't deleted")
	}

	// checkout-b is deleted: so is its snoopy pod.
	if err := cs.CoreV1().Pods("shop").Delete(ctx, "checkout-b", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		r.mu.Lock()
		s := r.owner["containerd://checkout-b"]
		r.mu.Unlock()
		if s.stopped() {
			return
		}
	}
	t.Error("the deleted pod's snoopy pod wasn't deleted")
}

func followRunner(cs *fake.Clientset) (*runner, func() []nodeTargets) {
	streams, _, _, _ := genericiooptions.NewTestIOStreams()
	o := &options{streams: streams}
	var mu sync.Mutex
	var launched []nodeTargets
	r := &runner{o: o, cs: cs, ns: "shop", debugNS: "shop", owner: map[string]*session{}, podOf: map[string]string{}, maxSessions: 10}
	r.launch = func(_ context.Context, n nodeTargets) error {
		mu.Lock()
		launched = append(launched, n)
		mu.Unlock()
		r.track(&session{o: o, node: n.node, ns: "shop", name: "snoopy-" + n.pods[0], ids: map[string]bool{}}, n.targets)
		return nil
	}
	return r, func() []nodeTargets {
		mu.Lock()
		defer mu.Unlock()
		return append([]nodeTargets(nil), launched...)
	}
}

// A pod that comes and goes within the settle time isn't traced: no snoopy
// pod is left for a pod that's gone.
func TestFollowGoneWhileSettling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cs := fake.NewClientset()
	r, launched := followRunner(cs)
	go r.follow(ctx, nil, metav1.ListOptions{}, 300*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	if _, err := cs.CoreV1().Pods("shop").Create(ctx, shopPod("checkout-a", "node-1", "checkout", corev1.PodRunning), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := cs.CoreV1().Pods("shop").Delete(ctx, "checkout-a", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	if got := launched(); len(got) != 0 {
		t.Errorf("launched for a pod that's gone: %+v", got)
	}
}

// Pods named alike, and a pod seen several times while settling, are
// traced once each.
func TestFollowPodsNamedAlike(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cs := fake.NewClientset()
	r, launched := followRunner(cs)
	go r.follow(ctx, nil, metav1.ListOptions{}, 300*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	for _, name := range []string{"checkout-ab", "checkout-a"} {
		p := shopPod(name, "node-1", "checkout", corev1.PodRunning)
		if _, err := cs.CoreV1().Pods("shop").Create(ctx, p, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		p.Labels["seen"] = "again"
		if _, err := cs.CoreV1().Pods("shop").Update(ctx, p, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	for deadline := time.Now().Add(5 * time.Second); len(launched()) == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	got := launched()
	if len(got) != 1 || len(got[0].pods) != 2 || len(got[0].targets) != 2 {
		t.Errorf("launched: %+v", got)
	}
}

// A pod deleted while there was no watch (between one that ended and the
// next) has no Deleted event; the next list shows it gone, and its snoopy
// pod is deleted.
func TestFollowGoneBetweenWatches(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := shopPod("checkout-a", "node-1", "checkout", corev1.PodRunning)
	cs := fake.NewClientset(first)
	watchers := make(chan *watch.FakeWatcher, 4)
	cs.PrependWatchReactor("pods", func(k8stesting.Action) (bool, watch.Interface, error) {
		w := watch.NewFake()
		watchers <- w
		return true, w, nil
	})
	r, _ := followRunner(cs)
	tgts, _ := targets(first, nil)
	s := &session{o: r.o, node: "node-1", ns: "shop", name: "snoopy-start", ids: map[string]bool{}}
	r.track(s, tgts)
	go r.follow(ctx, nil, metav1.ListOptions{}, 20*time.Millisecond)

	w := <-watchers
	if err := cs.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), "shop", "checkout-a"); err != nil {
		t.Fatal(err)
	}
	w.Stop() // the watch ends, with no event for the deletion
	<-watchers
	for deadline := time.Now().Add(5 * time.Second); !s.stopped(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the snoopy pod of a pod deleted between watches wasn't deleted")
		}
	}
}
