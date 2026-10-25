#!/bin/bash
# End-to-end test of kubectl snoopy on a kind cluster: builds snoopy's image
# from this tree and loads it into the cluster, starts a pod that makes
# HTTPS requests, and checks that the plugin traces it, cleans up after
# itself, and explains a namespace that doesn't allow privileged pods.
#
# Needs Docker, kind, kubectl and Go. Run from anywhere; it makes (or reuses)
# a cluster named snoopy-e2e, and KEEP_CLUSTER=1 leaves it when done.
#
# Only counts are printed, never what was captured (see AGENTS.md).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cluster=snoopy-e2e
image=ghcr.io/tks98/snoopy:e2e
tmp=$(mktemp -d)
cleanup() {
	rm -rf "$tmp"
	if [ -z "${KEEP_CLUSTER:-}" ]; then
		kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

kind get clusters 2>/dev/null | grep -qx "$cluster" || kind create cluster --name "$cluster" --wait 120s
kubectl config use-context "kind-$cluster" >/dev/null

arch=$(go env GOARCH)
mkdir -p "$tmp/image/linux/$arch"
(cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$tmp/image/linux/$arch/snoopy" .)
cp "$root/Dockerfile" "$tmp/image/"
# The Dockerfile copies the Java agent's jars too: built if there's a JDK,
# else empty, which this test (no --java) doesn't mind.
mkdir -p "$tmp/image/java/out"
if command -v javac >/dev/null && sh "$root/java/build.sh" >/dev/null 2>&1; then
	cp "$root"/java/out/snoopy-*.jar "$tmp/image/java/out/"
else
	touch "$tmp/image/java/out/snoopy-agent.jar" "$tmp/image/java/out/snoopy-hooks.jar"
fi
docker build -q --build-arg "TARGETPLATFORM=linux/$arch" -t "$image" "$tmp/image" >/dev/null
kind load docker-image "$image" --name "$cluster" >/dev/null
(cd "$here" && go build -o "$tmp/kubectl-snoopy" .)

kubectl delete pod client --ignore-not-found --wait >/dev/null
kubectl run client --image=curlimages/curl --restart=Never --command -- \
	sh -c 'while true; do curl -s --http1.1 -o /dev/null https://example.com; sleep 1; done' >/dev/null
kubectl wait --for=condition=Ready pod/client --timeout=120s >/dev/null

echo "== tracing pod client"
status=0
timeout 180 "$tmp/kubectl-snoopy" client --image "$image" --json --count 4 > "$tmp/out.json" 2> "$tmp/err" || status=$?
if [ "$status" -ne 0 ]; then
	cat "$tmp/err" >&2
	[ "$status" -eq 124 ] && fail "no 4 calls in 180 s"
	fail "kubectl snoopy exited with $status"
fi
grep -v '^{' "$tmp/err" || true
events=$(grep -c '^{' "$tmp/out.json" || true)
named=$(grep -c '"container_name":"client/client"' "$tmp/out.json" || true)
echo "events: $events, named client/client: $named"
[ "$events" -ge 4 ] || fail "expected 4 events"
[ "$named" -eq "$events" ] || fail "events without the pod's container name"

for i in $(seq 30); do
	left=$(kubectl get pods -A -l app.kubernetes.io/managed-by=kubectl-snoopy --no-headers 2>/dev/null | wc -l)
	[ "$left" -eq 0 ] && break
	sleep 1
done
[ "$left" -eq 0 ] || fail "$left snoopy pods left behind"
echo "no snoopy pods left"

echo "== a deployment's pods, and the same with -l"
kubectl delete deployment clients --ignore-not-found --wait >/dev/null
kubectl create deployment clients --image=curlimages/curl --replicas=2 -- \
	sh -c 'while true; do curl -s --http1.1 -o /dev/null https://example.com; sleep 1; done' >/dev/null
kubectl rollout status deployment/clients --timeout=120s >/dev/null
for target in deploy/clients "-l app=clients"; do
	status=0
	# shellcheck disable=SC2086 # -l and its value are two words
	timeout 180 "$tmp/kubectl-snoopy" $target --image "$image" --json --count 8 > "$tmp/out.json" 2> "$tmp/err" || status=$?
	[ "$status" -eq 0 ] || { cat "$tmp/err" >&2; fail "$target: kubectl snoopy exited with $status"; }
	pods=$(grep -o '"container_name":"clients-[^/"]*/curl"' "$tmp/out.json" | sort -u | wc -l)
	echo "$target: $(grep -c '^{' "$tmp/out.json") events, from $pods pods"
	[ "$pods" -eq 2 ] || fail "$target: events from $pods of the deployment's 2 pods"
done

echo "== following a rollout: the new pods are traced as they start"
old_pods=$(kubectl get pods -l app=clients -o jsonpath='{.items[*].metadata.name}')
"$tmp/kubectl-snoopy" deploy/clients --image "$image" --json > "$tmp/out.json" 2> "$tmp/err" &
plugin=$!
for i in $(seq 60); do grep -q tracing "$tmp/err" && break; sleep 1; done
kubectl rollout restart deployment/clients >/dev/null
kubectl rollout status deployment/clients --timeout=120s >/dev/null
sleep 15
kill -INT $plugin
wait $plugin || true
new_pods=$(kubectl get pods -l app=clients -o jsonpath='{.items[*].metadata.name}')
seen_new=0
for p in $new_pods; do
	case " $old_pods " in *" $p "*) continue ;; esac
	grep -q "\"container_name\":\"$p/curl\"" "$tmp/out.json" && seen_new=$((seen_new + 1))
done
echo "events from $seen_new of the rollout's new pods"
[ "$seen_new" -ge 1 ] || { cat "$tmp/err" >&2; fail "the rollout's new pods weren't traced"; }
for i in $(seq 30); do
	left=$(kubectl get pods -A -l app.kubernetes.io/managed-by=kubectl-snoopy --no-headers 2>/dev/null | wc -l)
	[ "$left" -eq 0 ] && break
	sleep 1
done
[ "$left" -eq 0 ] || fail "$left snoopy pods left behind after following"
kubectl delete deployment clients --wait=false >/dev/null

echo "== a namespace that doesn't allow privileged pods"
kubectl create namespace restricted --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label namespace restricted pod-security.kubernetes.io/enforce=baseline --overwrite >/dev/null
if "$tmp/kubectl-snoopy" client --image "$image" --debug-namespace restricted --count 1 > /dev/null 2> "$tmp/err"; then
	fail "the snoopy pod was created in a baseline namespace"
fi
grep -q -- "--debug-namespace" "$tmp/err" || { cat "$tmp/err" >&2; fail "no advice about --debug-namespace"; }
echo "explained: $(head -1 "$tmp/err" | cut -c1-100)"

echo "== --cleanup"
"$tmp/kubectl-snoopy" client --image "$image" --keep --count 1 > /dev/null 2>&1
"$tmp/kubectl-snoopy" --cleanup 2>&1 | grep -q "deleted default/snoopy-client-" || fail "--cleanup didn't delete the kept pod"
echo "deleted the kept pod"

echo PASS
