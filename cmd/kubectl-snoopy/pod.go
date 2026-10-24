package main

import (
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	managedByLabel = "app.kubernetes.io/managed-by"
	managedBy      = "kubectl-snoopy"
	targetKey      = "kubectl-snoopy/target"
	snoopyName     = "snoopy" // the container's name in the pod we make
	defaultImage   = "ghcr.io/tks98/snoopy"
)

// target is a container to trace: its runtime ID, as the pod's status has
// it (containerd://<id>), and the name it's shown by.
type target struct {
	id, name string
}

// targets returns the running containers of pod to trace: those named, or
// with none named, all of them, sidecars started as init containers
// included.
func targets(pod *corev1.Pod, names []string) ([]target, error) {
	statuses := slices.Concat(pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses)
	var out []target
	var notRunning []string
	for _, s := range statuses {
		if len(names) > 0 && !slices.Contains(names, s.Name) {
			continue
		}
		if s.State.Running == nil || s.ContainerID == "" {
			if len(names) > 0 || !isInit(pod, s.Name) {
				notRunning = append(notRunning, s.Name)
			}
			continue
		}
		out = append(out, target{id: s.ContainerID, name: pod.Name + "/" + s.Name})
	}
	for _, n := range names {
		if !slices.ContainsFunc(statuses, func(s corev1.ContainerStatus) bool { return s.Name == n }) {
			return nil, fmt.Errorf("pod %s has no container %q", pod.Name, n)
		}
	}
	if len(out) == 0 {
		if len(notRunning) > 0 {
			return nil, fmt.Errorf("no container of pod %s is running (%s)", pod.Name, strings.Join(notRunning, ", "))
		}
		return nil, fmt.Errorf("pod %s has no running containers", pod.Name)
	}
	return out, nil
}

func isInit(pod *corev1.Pod, name string) bool {
	return slices.ContainsFunc(pod.Spec.InitContainers, func(c corev1.Container) bool { return c.Name == name })
}

// snoopyArgs returns snoopy's arguments: the containers to trace, then the
// rest as given.
func snoopyArgs(targets []target, rest []string) []string {
	var args []string
	for _, t := range targets {
		args = append(args, "--container", t.id+"="+t.name)
	}
	return append(args, rest...)
}

// snoopyPod returns a pod that runs snoopy on node, for what it traces
// there (say, "shop/pod checkout-7d9f"), named after name: it shares the
// node's PID namespace and is privileged, which snoopy needs to load its
// eBPF program and see other pods' processes.
func snoopyPod(node, name, what, namespace, image string, args []string, deadline time.Duration) *corev1.Pod {
	privileged := true
	noToken := false
	grace := int64(5)
	pull := corev1.PullIfNotPresent
	if tag := imageTag(image); tag == "" || tag == "latest" {
		pull = corev1.PullAlways
	}
	if len(name) > 40 {
		name = name[:40]
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "snoopy-" + strings.TrimSuffix(name, "-") + "-",
			Namespace:    namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "snoopy",
				managedByLabel:           managedBy,
			},
			Annotations: map[string]string{targetKey: what},
		},
		Spec: corev1.PodSpec{
			NodeName:                      node,
			HostPID:                       true,
			RestartPolicy:                 corev1.RestartPolicyNever,
			AutomountServiceAccountToken:  &noToken,
			EnableServiceLinks:            &noToken,
			TerminationGracePeriodSeconds: &grace,
			// Wherever the target runs, whatever the node's taints.
			Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			Containers: []corev1.Container{{
				Name:                     snoopyName,
				Image:                    image,
				ImagePullPolicy:          pull,
				Args:                     args,
				SecurityContext:          &corev1.SecurityContext{Privileged: &privileged},
				TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
			}},
		},
	}
	if deadline > 0 {
		// So a pod left behind by a plugin that was killed goes away anyway.
		secs := int64(deadline / time.Second)
		pod.Spec.ActiveDeadlineSeconds = &secs
	}
	return pod
}

// imageTag returns an image reference's tag, or "" if it has none (or is
// pinned by digest).
func imageTag(image string) string {
	if strings.Contains(image, "@") {
		return "digest"
	}
	i := strings.LastIndex(image, ":")
	if i < 0 || strings.Contains(image[i:], "/") {
		return ""
	}
	return image[i+1:]
}

// explainCreate says why the snoopy pod couldn't be created, when the
// API's reason is one users can act on: most often, Pod Security Admission,
// which allows privileged pods only in namespaces that say so.
func explainCreate(err error, namespace string) error {
	msg := err.Error()
	if strings.Contains(msg, "violates PodSecurity") {
		return fmt.Errorf("namespace %s doesn't allow privileged pods, which snoopy needs; run with "+
			"--debug-namespace set to one that does (such as kube-system, or one labeled "+
			"pod-security.kubernetes.io/enforce=privileged)\n  %v", namespace, err)
	}
	if strings.Contains(msg, "forbidden") {
		return fmt.Errorf("not allowed to create the snoopy pod in namespace %s (it needs create on pods, "+
			"and pods/attach); see kubectl snoopy --help\n  %v", namespace, err)
	}
	return fmt.Errorf("create the snoopy pod: %w", err)
}

// waitingProblem returns why a pod's container can't start, if it's a
// reason that won't go away by waiting, or "".
func waitingProblem(pod *corev1.Pod) string {
	for _, s := range pod.Status.ContainerStatuses {
		if w := s.State.Waiting; w != nil {
			switch w.Reason {
			case "ErrImagePull", "ImagePullBackOff", "InvalidImageName", "CreateContainerConfigError", "CreateContainerError":
				return w.Reason + ": " + w.Message
			}
		}
	}
	return ""
}
