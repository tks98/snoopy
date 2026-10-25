package main

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericiooptions"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestFileToStdout(t *testing.T) {
	for args, want := range map[string]string{
		"--quiet --har -":        "--har",
		"--har=-":                "--har",
		"-pcap -":                "--pcap",
		"--har out.har":          "",
		"--max-size 65536":       "",
		"--host - --verbose":     "",
		"--quiet --pcap=- --hex": "--pcap",
	} {
		if got := fileToStdout(strings.Fields(args)); got != want {
			t.Errorf("%s: %q, want %q", args, got, want)
		}
	}
}

func TestExplainAPI(t *testing.T) {
	refused := &url.Error{Op: "Get", URL: "https://127.0.0.1:6443/api/v1/namespaces/shop/pods/x", Err: errors.New("connection refused")}
	if err := explainAPI(refused); !strings.Contains(err.Error(), "does kubectl get pods work?") || !errors.Is(err, refused) {
		t.Errorf("refused: %v", err)
	}
	other := errors.New("pods \"x\" not found")
	if err := explainAPI(other); err != other {
		t.Errorf("other: %v", err)
	}
}

func testOptions() *options {
	streams, _, _, _ := genericiooptions.NewTestIOStreams()
	return &options{streams: streams}
}

// Ctrl-C while a snoopy pod is being created: it's deleted when it is, and
// snoopy isn't run in it.
func TestStartWhileStopping(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if pod := a.(k8stesting.CreateAction).GetObject().(*corev1.Pod); pod.Name == "" {
			pod.Name = pod.GenerateName + "x"
		}
		return false, nil, nil
	})
	r := &runner{o: testOptions(), cs: cs, ns: "shop", debugNS: "shop", owner: map[string]*session{}, podOf: map[string]string{}}
	r.removeAll()
	n := nodeTargets{node: "node-1", pods: []string{"checkout-a"}, targets: []target{{"containerd://a", "checkout-a/app"}}}
	if err := r.start(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	r.wg.Wait()
	left, _ := cs.CoreV1().Pods("shop").List(context.Background(), metav1.ListOptions{})
	if len(left.Items) != 0 {
		t.Errorf("left: %v", left.Items)
	}
}

// A snoopy pod deleted (Ctrl-C) before it ran isn't a failure.
func TestRunStoppedBeforeRunning(t *testing.T) {
	pending := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "snoopy-x", Namespace: "shop"}, Status: corev1.PodStatus{Phase: corev1.PodPending}}
	cs := fake.NewClientset(pending)
	s := &session{o: testOptions(), node: "node-1", ns: "shop", name: "snoopy-x", ids: map[string]bool{}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error)
	go func() { done <- s.run(ctx, nil, cs, nil, nil) }()
	time.Sleep(100 * time.Millisecond)
	s.remove(cs)
	if err := <-done; err != nil {
		t.Errorf("stopped before it ran: %v", err)
	}
}

// A snoopy pod that ended by itself says why.
func TestEnded(t *testing.T) {
	failed := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "snoopy-x", Namespace: "shop"}, Status: corev1.PodStatus{
		Phase: corev1.PodFailed,
		ContainerStatuses: []corev1.ContainerStatus{{Name: snoopyName, State: corev1.ContainerState{
			Terminated: &corev1.ContainerStateTerminated{ExitCode: 2, Reason: "Error"}}}},
	}}
	cs := fake.NewClientset(failed)
	s := &session{o: testOptions(), node: "node-1", ns: "shop", name: "snoopy-x"}
	err := s.ended(context.Background(), cs)
	if err == nil || !strings.Contains(err.Error(), "exited with status 2") {
		t.Errorf("got %v", err)
	}
	running := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "snoopy-y", Namespace: "shop"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	cs = fake.NewClientset(running)
	if err := (&session{o: testOptions(), ns: "shop", name: "snoopy-y"}).ended(context.Background(), cs); err != nil {
		t.Errorf("running: %v", err)
	}
}

// A pod being deleted by one caller isn't taken as deleted by another until
// it is: the plugin would exit with the deletion still on its way.
func TestRemoveWaits(t *testing.T) {
	cs := fake.NewClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "snoopy-x", Namespace: "shop"}})
	release := make(chan struct{})
	cs.PrependReactor("delete", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		<-release
		return false, nil, nil
	})
	s := &session{o: testOptions(), ns: "shop", name: "snoopy-x"}
	go s.remove(cs)
	time.Sleep(50 * time.Millisecond)
	second := make(chan struct{})
	go func() {
		s.remove(cs)
		close(second)
	}()
	select {
	case <-second:
		t.Fatal("the second remove returned before the pod was deleted")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-second
	if _, err := cs.CoreV1().Pods("shop").Get(context.Background(), "snoopy-x", metav1.GetOptions{}); err == nil {
		t.Error("not deleted")
	}
}
