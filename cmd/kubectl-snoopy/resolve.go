package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

// kinds are the resources a target can name as KIND/NAME, by kubectl's
// names for them, short and long; each selects pods by its selector.
var kinds = map[string]string{
	"pod": "pod", "pods": "pod", "po": "pod",
	"deployment": "deployment", "deployments": "deployment", "deploy": "deployment",
	"statefulset": "statefulset", "statefulsets": "statefulset", "sts": "statefulset",
	"daemonset": "daemonset", "daemonsets": "daemonset", "ds": "daemonset",
	"replicaset": "replicaset", "replicasets": "replicaset", "rs": "replicaset",
	"job": "job", "jobs": "job",
	"service": "service", "services": "service", "svc": "service",
}

// resolvePods returns the running pods a target selects: a pod by name, a
// KIND/NAME whose selector picks them, or with selector set (-l), the pods
// it matches. what describes the target, for messages.
func resolvePods(ctx context.Context, cs kubernetes.Interface, ns, target, selector string) (pods []corev1.Pod, what string, err error) {
	switch {
	case target != "" && selector != "":
		return nil, "", fmt.Errorf("give a pod, KIND/NAME or -l, not both %s and -l", target)
	case selector != "":
		what = "pods matching " + selector
	case !strings.Contains(target, "/"):
		pod, err := cs.CoreV1().Pods(ns).Get(ctx, target, metav1.GetOptions{})
		if err != nil {
			return nil, "", err
		}
		if pod.Spec.NodeName == "" || pod.Status.Phase != corev1.PodRunning {
			return nil, "", fmt.Errorf("pod %s isn't running (it's %s)", target, strings.ToLower(string(pod.Status.Phase)))
		}
		return []corev1.Pod{*pod}, "pod " + target, nil
	default:
		kind, name, _ := strings.Cut(target, "/")
		k, ok := kinds[strings.ToLower(kind)]
		if !ok {
			return nil, "", fmt.Errorf("%s: kubectl snoopy knows pods, deployments, statefulsets, daemonsets, replicasets, jobs and services", kind)
		}
		if k == "pod" {
			return resolvePods(ctx, cs, ns, name, "")
		}
		if selector, err = selectorOf(ctx, cs, ns, k, name); err != nil {
			return nil, "", err
		}
		what = k + " " + name
	}

	list, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, "", err
	}
	notRunning := 0
	for _, p := range list.Items {
		if p.Spec.NodeName != "" && p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil {
			pods = append(pods, p)
		} else {
			notRunning++
		}
	}
	if len(pods) == 0 {
		if notRunning > 0 {
			return nil, "", fmt.Errorf("none of the %d pods of %s is running", notRunning, what)
		}
		return nil, "", fmt.Errorf("no pods in namespace %s for %s", ns, what)
	}
	return pods, what, nil
}

// selectorOf returns the label selector of a workload or service, as a
// string for listing pods with.
func selectorOf(ctx context.Context, cs kubernetes.Interface, ns, kind, name string) (string, error) {
	get := metav1.GetOptions{}
	var sel *metav1.LabelSelector
	switch kind {
	case "deployment":
		d, err := cs.AppsV1().Deployments(ns).Get(ctx, name, get)
		if err != nil {
			return "", err
		}
		sel = d.Spec.Selector
	case "statefulset":
		s, err := cs.AppsV1().StatefulSets(ns).Get(ctx, name, get)
		if err != nil {
			return "", err
		}
		sel = s.Spec.Selector
	case "daemonset":
		d, err := cs.AppsV1().DaemonSets(ns).Get(ctx, name, get)
		if err != nil {
			return "", err
		}
		sel = d.Spec.Selector
	case "replicaset":
		r, err := cs.AppsV1().ReplicaSets(ns).Get(ctx, name, get)
		if err != nil {
			return "", err
		}
		sel = r.Spec.Selector
	case "job":
		j, err := cs.BatchV1().Jobs(ns).Get(ctx, name, get)
		if err != nil {
			return "", err
		}
		sel = j.Spec.Selector
	case "service":
		s, err := cs.CoreV1().Services(ns).Get(ctx, name, get)
		if err != nil {
			return "", err
		}
		if len(s.Spec.Selector) == 0 {
			return "", fmt.Errorf("service %s has no selector, so no pods of its own", name)
		}
		return labels.SelectorFromSet(s.Spec.Selector).String(), nil
	}
	if sel == nil {
		return "", fmt.Errorf("%s %s has no selector", kind, name)
	}
	s, err := metav1.LabelSelectorAsSelector(sel)
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", kind, name, err)
	}
	return s.String(), nil
}

// nodeTargets are the containers to trace on one node.
type nodeTargets struct {
	node    string
	pods    []string // their names
	targets []target
}

// byNode groups the containers to trace of pods by the node they run on,
// in the nodes' order by name. A pod that lacks the containers asked for is
// left out, and said so of with warn, unless it's the only one.
func byNode(pods []corev1.Pod, containers []string, warn func(string, ...any)) ([]nodeTargets, error) {
	nodes := map[string]*nodeTargets{}
	for i := range pods {
		p := &pods[i]
		tgts, err := targets(p, containers)
		if err != nil {
			if len(pods) == 1 {
				return nil, err
			}
			warn("leaving out pod %s: %v", p.Name, err)
			continue
		}
		n := nodes[p.Spec.NodeName]
		if n == nil {
			n = &nodeTargets{node: p.Spec.NodeName}
			nodes[p.Spec.NodeName] = n
		}
		n.pods = append(n.pods, p.Name)
		n.targets = append(n.targets, tgts...)
	}
	var out []nodeTargets
	for _, n := range nodes {
		out = append(out, *n)
	}
	slices.SortFunc(out, func(a, b nodeTargets) int { return strings.Compare(a.node, b.node) })
	if len(out) == 0 {
		return nil, fmt.Errorf("none of the pods has the containers %s running", strings.Join(containers, ", "))
	}
	return out, nil
}
