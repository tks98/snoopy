package main

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func shopPod(name, node, app string, phase corev1.PodPhase) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "shop", Labels: map[string]string{"app": app}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: phase, ContainerStatuses: []corev1.ContainerStatus{{
			Name: "app", ContainerID: "containerd://" + name, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}},
	}
}

func shop() *fake.Clientset {
	return fake.NewClientset(
		shopPod("checkout-a", "node-1", "checkout", corev1.PodRunning),
		shopPod("checkout-b", "node-2", "checkout", corev1.PodRunning),
		shopPod("checkout-c", "node-1", "checkout", corev1.PodRunning),
		shopPod("checkout-d", "node-2", "checkout", corev1.PodPending),
		shopPod("cart-a", "node-1", "cart", corev1.PodRunning),
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "checkout", Namespace: "shop"},
			Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "checkout"}}}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "cart", Namespace: "shop"},
			Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "cart"}}},
	)
}

func names(pods []corev1.Pod) []string {
	var out []string
	for _, p := range pods {
		out = append(out, p.Name)
	}
	slices.Sort(out)
	return out
}

func TestResolvePods(t *testing.T) {
	ctx := context.Background()
	cs := shop()
	for _, c := range []struct {
		target, selector string
		want             []string
	}{
		{"checkout-b", "", []string{"checkout-b"}},
		{"pod/checkout-b", "", []string{"checkout-b"}},
		{"deploy/checkout", "", []string{"checkout-a", "checkout-b", "checkout-c"}}, // not the pending one
		{"deployment/checkout", "", []string{"checkout-a", "checkout-b", "checkout-c"}},
		{"svc/cart", "", []string{"cart-a"}},
		{"", "app=cart", []string{"cart-a"}},
		{"", "app in (cart,checkout)", []string{"cart-a", "checkout-a", "checkout-b", "checkout-c"}},
	} {
		pods, _, err := resolvePods(ctx, cs, "shop", c.target, c.selector)
		if err != nil || !reflect.DeepEqual(names(pods), c.want) {
			t.Errorf("%q -l %q: %v, %v", c.target, c.selector, names(pods), err)
		}
	}
	for _, c := range []struct{ target, selector, want string }{
		{"checkout-d", "", "isn't running"},
		{"deploy/nope", "", "not found"},
		{"cronjob/x", "", "knows pods"},
		{"", "app=none", "no pods"},
		{"checkout-a", "app=cart", "not both"},
	} {
		if _, _, err := resolvePods(ctx, cs, "shop", c.target, c.selector); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q -l %q: %v, want %q", c.target, c.selector, err, c.want)
		}
	}
}

func TestByNode(t *testing.T) {
	pods, _, err := resolvePods(context.Background(), shop(), "shop", "deploy/checkout", "")
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := byNode(pods, nil, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 || nodes[0].node != "node-1" || len(nodes[0].targets) != 2 || nodes[1].node != "node-2" || len(nodes[1].targets) != 1 {
		t.Errorf("nodes: %+v", nodes)
	}
	var warned []string
	if _, err := byNode(pods, []string{"sidecar"}, func(f string, a ...any) { warned = append(warned, f) }); err == nil || len(warned) != 3 {
		t.Errorf("-c sidecar, which none has: %v, %d warnings", err, len(warned))
	}
}

// Two streams writing at once: each event lands whole.
func TestMerger(t *testing.T) {
	var out bytes.Buffer
	m := newMerger(&out, true)
	m.idle = time.Hour
	a, b := m.stream(), m.stream()
	a.Write([]byte("12:00:00.000001 event a1\nline two"))
	b.Write([]byte("12:00:00.000002 event b1\n\n12:00:00.000003 event b2"))
	a.Write([]byte("\n\n12:00:00.000004 event a2\n\n"))
	b.Write([]byte(" continued\n\n"))
	a.Flush()
	b.Flush()
	want := "12:00:00.000002 event b1\n\n12:00:00.000001 event a1\nline two\n\n12:00:00.000004 event a2\n\n12:00:00.000003 event b2 continued\n\n"
	if out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}

	out.Reset()
	p := &prefixWriter{m: newMerger(&out, false), prefix: []byte("[node-1] ")}
	p.Write([]byte("snoopy: tracing\nsnoopy: capt"))
	p.Write([]byte("ured 3 calls\n"))
	if out.String() != "[node-1] snoopy: tracing\n[node-1] snoopy: captured 3 calls\n" {
		t.Errorf("prefixed: %q", out.String())
	}
}
