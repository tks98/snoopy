package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func testPod() *corev1.Pod {
	running := corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}
	done := corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "checkout-7d9f", Namespace: "shop"},
		Spec: corev1.PodSpec{
			NodeName:       "pool-a-3",
			InitContainers: []corev1.Container{{Name: "migrate"}, {Name: "proxy"}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", ContainerID: "containerd://aaa", State: running},
				{Name: "metrics", ContainerID: "containerd://bbb", State: running},
			},
			InitContainerStatuses: []corev1.ContainerStatus{
				{Name: "migrate", ContainerID: "containerd://ccc", State: done},
				{Name: "proxy", ContainerID: "containerd://ddd", State: running}, // a sidecar
			},
		},
	}
}

func TestTargets(t *testing.T) {
	pod := testPod()
	got, err := targets(pod, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []target{
		{"containerd://aaa", "checkout-7d9f/app"},
		{"containerd://bbb", "checkout-7d9f/metrics"},
		{"containerd://ddd", "checkout-7d9f/proxy"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("all: got %v, want %v", got, want)
	}

	got, err = targets(pod, []string{"app"})
	if err != nil || len(got) != 1 || got[0].id != "containerd://aaa" {
		t.Errorf("-c app: %v, %v", got, err)
	}
	if _, err := targets(pod, []string{"nope"}); err == nil || !strings.Contains(err.Error(), `no container "nope"`) {
		t.Errorf("-c nope: %v", err)
	}
	if _, err := targets(pod, []string{"migrate"}); err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Errorf("-c migrate, which has finished: %v", err)
	}
}

func TestSnoopyPod(t *testing.T) {
	args := snoopyArgs([]target{{"containerd://aaa", "checkout-7d9f/app"}}, []string{"--brief"})
	if want := []string{"--container", "containerd://aaa=checkout-7d9f/app", "--brief"}; !reflect.DeepEqual(args, want) {
		t.Errorf("args: %q", args)
	}
	pod := snoopyPod(testPod(), "kube-system", "ghcr.io/tks98/snoopy:2.6.0", args, time.Hour)
	spec := pod.Spec
	c := spec.Containers[0]
	switch {
	case pod.Namespace != "kube-system" || !strings.HasPrefix(pod.GenerateName, "snoopy-checkout-7d9f-"):
		t.Errorf("name: %s/%s", pod.Namespace, pod.GenerateName)
	case pod.Labels[managedByLabel] != managedBy || pod.Annotations[targetKey] != "shop/checkout-7d9f":
		t.Errorf("labels %v, annotations %v", pod.Labels, pod.Annotations)
	case spec.NodeName != "pool-a-3" || !spec.HostPID || spec.RestartPolicy != corev1.RestartPolicyNever:
		t.Errorf("spec: %+v", spec)
	case c.SecurityContext == nil || c.SecurityContext.Privileged == nil || !*c.SecurityContext.Privileged:
		t.Error("not privileged")
	case *spec.AutomountServiceAccountToken || *spec.ActiveDeadlineSeconds != 3600:
		t.Errorf("token %v, deadline %v", *spec.AutomountServiceAccountToken, *spec.ActiveDeadlineSeconds)
	case len(spec.Tolerations) != 1 || spec.Tolerations[0].Operator != corev1.TolerationOpExists:
		t.Errorf("tolerations: %v", spec.Tolerations)
	case c.ImagePullPolicy != corev1.PullIfNotPresent || !reflect.DeepEqual(c.Args, args):
		t.Errorf("container: %+v", c)
	}

	long := testPod()
	long.Name = strings.Repeat("x", 60)
	if p := snoopyPod(long, "shop", "snoopy", nil, 0); len(p.GenerateName) > 63-5 || p.Spec.ActiveDeadlineSeconds != nil {
		t.Errorf("long name: %q, deadline %v", p.GenerateName, p.Spec.ActiveDeadlineSeconds)
	}
}

func TestImagePull(t *testing.T) {
	for image, want := range map[string]corev1.PullPolicy{
		"ghcr.io/tks98/snoopy:2.6.0":       corev1.PullIfNotPresent,
		"ghcr.io/tks98/snoopy:latest":      corev1.PullAlways,
		"ghcr.io/tks98/snoopy":             corev1.PullAlways,
		"registry:5000/snoopy":             corev1.PullAlways,
		"registry:5000/snoopy:e2e":         corev1.PullIfNotPresent,
		"ghcr.io/tks98/snoopy@sha256:abcd": corev1.PullIfNotPresent,
	} {
		if got := snoopyPod(testPod(), "shop", image, nil, 0).Spec.Containers[0].ImagePullPolicy; got != want {
			t.Errorf("%s: %s, want %s", image, got, want)
		}
	}
}

func TestExplainCreate(t *testing.T) {
	psa := errors.New(`pods "snoopy-x" is forbidden: violates PodSecurity "baseline:latest": privileged`)
	if err := explainCreate(psa, "shop"); !strings.Contains(err.Error(), "--debug-namespace") {
		t.Errorf("PSA: %v", err)
	}
	rbac := errors.New(`pods is forbidden: User "dev" cannot create resource "pods"`)
	if err := explainCreate(rbac, "shop"); !strings.Contains(err.Error(), "pods/attach") {
		t.Errorf("RBAC: %v", err)
	}
}

func TestPassed(t *testing.T) {
	o := &options{brief: true, verbose: true, hosts: []string{"example.com"}, ports: []string{"443"}, count: 3}
	want := []string{"--brief", "--verbose", "--host", "example.com", "--port", "443", "--count", "3"}
	if got := o.passed(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q", got)
	}
}

func TestCleanup(t *testing.T) {
	mine := func(ns, name string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns,
			Labels: map[string]string{managedByLabel: managedBy}, Annotations: map[string]string{targetKey: "shop/x"}}}
	}
	other := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "shop"}}
	cs := fake.NewClientset(mine("shop", "snoopy-x-1"), mine("kube-system", "snoopy-x-2"), other)
	var out bytes.Buffer
	if err := cleanup(context.Background(), cs, "", &out); err != nil {
		t.Fatal(err)
	}
	left, _ := cs.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if len(left.Items) != 1 || left.Items[0].Name != "app" {
		t.Errorf("left: %v", left.Items)
	}
	if !strings.Contains(out.String(), "deleted kube-system/snoopy-x-2 (for shop/x)") {
		t.Errorf("output: %s", out.String())
	}
}
