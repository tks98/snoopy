#!/bin/bash
# End-to-end test of kubectl snoopy on a kind cluster: builds snoopy's image
# from this tree and loads it into the cluster, starts an HTTPS server and
# pods that make requests to it, and checks that the plugin traces them,
# keeps what it captures out of the snoopy pods' logs, cleans up after
# itself, and explains what goes wrong.
#
# Needs Docker, kind, kubectl and Go. Run from anywhere; it makes (or reuses)
# a cluster named snoopy-e2e, and KEEP_CLUSTER=1 leaves it when done. It
# works in a namespace of its own, E2E_NAMESPACE (snoopy-e2e), deleted when
# done, and nothing in it talks to anything outside the cluster.
#
# Only counts are printed, never what was captured (see AGENTS.md).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cluster=snoopy-e2e
ns=${E2E_NAMESPACE:-snoopy-e2e}
image=ghcr.io/tks98/snoopy:e2e
# Pinned, so that a new release of one doesn't change what's tested.
openssl_image=alpine/openssl:3.5.8@sha256:3f25da71f70eba788067daac3f3df03bd1de7a7c52ed89fa93b94ad2c92d986b
curl_image=curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777
java_image=eclipse-temurin:21.0.12_8-jdk@sha256:92a2a4d7a928d057e7bd999c418d66c26a34eb9a0442f3ab67721c3f88110b2d
tmp=$(mktemp -d)
plugin=
cleanup() {
	if [ -n "$plugin" ]; then kill "$plugin" 2>/dev/null || true; fi
	rm -rf "$tmp"
	if [ -z "${KEEP_CLUSTER:-}" ]; then
		kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
	else
		kubectl delete namespace "$ns" "$ns-restricted" --ignore-not-found --wait=false >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
k() { kubectl -n "$ns" "$@"; }
# Not for running in the background: Ctrl-C (kill -INT) would go to the
# subshell running it, and not to the plugin.
snoopy() { "$tmp/kubectl-snoopy" -n "$ns" --image "$image" "$@"; }

# until_ok SECONDS CMD...: runs CMD every second until it succeeds, or
# fails after SECONDS.
until_ok() {
	local n=$1
	shift
	for _ in $(seq "$n"); do
		"$@" && return 0
		sleep 1
	done
	return 1
}
snoopy_pods() { k get pods -l app.kubernetes.io/managed-by=kubectl-snoopy --no-headers 2>/dev/null | wc -l; }
no_snoopy_pods() { [ "$(snoopy_pods)" -eq 0 ]; }

kind get clusters 2>/dev/null | grep -qx "$cluster" || kind create cluster --name "$cluster" --wait 120s
kubectl config use-context "kind-$cluster" >/dev/null

arch=$(go env GOARCH)
mkdir -p "$tmp/image/linux/$arch"
(cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$tmp/image/linux/$arch/snoopy" .)
cp "$root/Dockerfile" "$tmp/image/"
# The Dockerfile copies the Java agent's jars too: built if there's a JDK,
# else empty, which the tests without --java don't mind.
mkdir -p "$tmp/image/java/out"
java=false
if command -v javac >/dev/null && sh "$root/java/build.sh" >/dev/null 2>&1; then
	cp "$root"/java/out/snoopy-*.jar "$tmp/image/java/out/"
	java=true
elif [ -n "${SNOOPY_E2E_JAVA:-}" ]; then
	fail "SNOOPY_E2E_JAVA is set, but the Java agent can't be built here (no JDK 17 or later?)"
else
	touch "$tmp/image/java/out/snoopy-agent.jar" "$tmp/image/java/out/snoopy-hooks.jar"
fi
docker build -q --build-arg "TARGETPLATFORM=linux/$arch" -t "$image" "$tmp/image" >/dev/null
kind load docker-image "$image" --name "$cluster" >/dev/null
(cd "$here" && go build -o "$tmp/kubectl-snoopy" .)

kubectl delete namespace "$ns" "$ns-restricted" --ignore-not-found --wait >/dev/null
kubectl create namespace "$ns" >/dev/null

# An HTTPS server in the cluster, with a certificate of its own making:
# openssl s_server, answering each request with a page about the
# connection.
k apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tls-server
spec:
  selector:
    matchLabels: {app: tls-server}
  template:
    metadata:
      labels: {app: tls-server}
    spec:
      initContainers:
        - name: cert
          image: $openssl_image
          args: [req, -x509, -newkey, ec, -pkeyopt, "ec_paramgen_curve:P-256", -nodes, -days, "2",
                 -subj, /CN=tls-server, -addext, "subjectAltName=DNS:tls-server",
                 -keyout, /certs/key.pem, -out, /certs/cert.pem]
          volumeMounts: [{name: certs, mountPath: /certs}]
      containers:
        - name: server
          image: $openssl_image
          args: [s_server, -quiet, -www, -accept, "8443", -cert, /certs/cert.pem, -key, /certs/key.pem]
          ports: [{containerPort: 8443}]
          readinessProbe:
            tcpSocket: {port: 8443}
            periodSeconds: 1
          volumeMounts: [{name: certs, mountPath: /certs}]
      volumes:
        - {name: certs, emptyDir: {}}
---
apiVersion: v1
kind: Service
metadata:
  name: tls-server
spec:
  selector: {app: tls-server}
  ports: [{port: 443, targetPort: 8443}]
YAML
k rollout status deployment/tls-server --timeout=120s >/dev/null

request='while true; do curl -sk --http1.1 -o /dev/null https://tls-server/; sleep 1; done'
k run client --image="$curl_image" --restart=Never --command -- sh -c "$request" >/dev/null
k wait --for=condition=Ready pod/client --timeout=120s >/dev/null

echo "== tracing pod client"
status=0
timeout 180 "$tmp/kubectl-snoopy" -n "$ns" client --image "$image" --json --count 4 > "$tmp/out.json" 2> "$tmp/err" || status=$?
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
until_ok 30 no_snoopy_pods || fail "snoopy pods left behind"
echo "no snoopy pods left"

echo "== what snoopy captures isn't in the snoopy pod's log, or its status"
snoopy client --json --count 2 --keep > "$tmp/out.json" 2> "$tmp/err" || { cat "$tmp/err" >&2; fail "kubectl snoopy --keep failed"; }
kept=$(k get pods -l app.kubernetes.io/managed-by=kubectl-snoopy -o jsonpath='{.items[0].metadata.name}')
[ -n "$kept" ] || fail "--keep left no pod"
logged=$(k logs "$kept" | wc -c)
message=$(k get pod "$kept" -o jsonpath='{.status.containerStatuses[0].state.terminated.message}' | wc -c)
echo "events: $(grep -c '^{' "$tmp/out.json"), bytes in the snoopy pod's log: $logged, in its termination message: $message"
[ "$logged" -eq 0 ] || fail "the snoopy pod's log isn't empty"
[ "$message" -eq 0 ] || fail "the snoopy pod's status has a termination message"

echo "== --cleanup"
"$tmp/kubectl-snoopy" -n "$ns" --cleanup 2>&1 | grep -q "deleted $ns/$kept" || fail "--cleanup didn't delete the kept pod"
echo "deleted the kept pod"

echo "== a deployment's pods, and the same with -l"
k create deployment clients --image="$curl_image" --replicas=2 -- sh -c "$request" >/dev/null
k rollout status deployment/clients --timeout=120s >/dev/null
for target in deploy/clients "-l app=clients"; do
	status=0
	# shellcheck disable=SC2086 # -l and its value are two words
	timeout 180 "$tmp/kubectl-snoopy" -n "$ns" $target --image "$image" --json --count 8 > "$tmp/out.json" 2> "$tmp/err" || status=$?
	[ "$status" -eq 0 ] || { cat "$tmp/err" >&2; fail "$target: kubectl snoopy exited with $status"; }
	pods=$(grep -o '"container_name":"clients-[^/"]*/curl"' "$tmp/out.json" | sort -u | wc -l)
	echo "$target: $(grep -c '^{' "$tmp/out.json") events, from $pods pods"
	[ "$pods" -eq 2 ] || fail "$target: events from $pods of the deployment's 2 pods"
done

echo "== following a rollout: the new pods are traced as they start"
old_pods=$(k get pods -l app=clients -o jsonpath='{.items[*].metadata.name}')
"$tmp/kubectl-snoopy" -n "$ns" --image "$image" deploy/clients --json > "$tmp/out.json" 2> "$tmp/err" &
plugin=$!
until_ok 60 grep -q tracing "$tmp/err" || { cat "$tmp/err" >&2; fail "snoopy didn't start tracing"; }
k rollout restart deployment/clients >/dev/null
k rollout status deployment/clients --timeout=120s >/dev/null
new_pods=$(k get pods -l app=clients --field-selector=status.phase=Running -o jsonpath='{.items[*].metadata.name}')
both_new_seen() {
	local seen=0 p
	for p in $new_pods; do
		case " $old_pods " in *" $p "*) continue ;; esac
		grep -q "\"container_name\":\"$p/curl\"" "$tmp/out.json" && seen=$((seen + 1))
	done
	[ "$seen" -ge 2 ]
}
until_ok 90 both_new_seen || { cat "$tmp/err" >&2; fail "the rollout's new pods weren't both traced"; }
echo "events from both of the rollout's new pods"
# The old pods' snoopy pod goes with them, leaving the new pods' (one, or
# one each).
until_ok 60 sh -c '[ "$(kubectl -n "$0" get pods -l app.kubernetes.io/managed-by=kubectl-snoopy --no-headers | wc -l)" -le 2 ]' "$ns" ||
	fail "the old pods' snoopy pod is still there"
kill -INT $plugin
status=0
wait $plugin || status=$?
plugin=
[ "$status" -eq 0 ] || { cat "$tmp/err" >&2; fail "kubectl snoopy exited with $status on Ctrl-C"; }
until_ok 30 no_snoopy_pods || fail "snoopy pods left behind after following"
echo "stopped with status 0, no snoopy pods left"
k delete deployment clients --wait=false >/dev/null

echo "== Ctrl-C as soon as the snoopy pod is made"
"$tmp/kubectl-snoopy" -n "$ns" --image "$image" client --json > /dev/null 2> "$tmp/err" &
plugin=$!
until_ok 30 grep -q "starting snoopy" "$tmp/err" || fail "no snoopy pod started"
kill -INT $plugin
status=0
wait $plugin || status=$?
plugin=
[ "$status" -eq 0 ] || { cat "$tmp/err" >&2; fail "kubectl snoopy exited with $status on an early Ctrl-C"; }
until_ok 30 no_snoopy_pods || fail "snoopy pods left behind after an early Ctrl-C"
echo "stopped with status 0, no snoopy pods left"

echo "== an image that can't be pulled is said so of, not waited on"
status=0
"$tmp/kubectl-snoopy" -n "$ns" client --image ghcr.io/tks98/snoopy:no-such-tag > /dev/null 2> "$tmp/err" &
plugin=$!
until_ok 90 grep -q "ErrImagePull\|ImagePullBackOff" "$tmp/err" || { cat "$tmp/err" >&2; fail "no word of the image pull failing"; }
kill -INT $plugin
wait $plugin || status=$?
plugin=
[ "$status" -eq 1 ] || { cat "$tmp/err" >&2; fail "kubectl snoopy exited with $status, not 1, after a failed pull"; }
echo "explained: $(grep -m1 -o 'ErrImagePull\|ImagePullBackOff' "$tmp/err")"
until_ok 30 no_snoopy_pods || fail "snoopy pods left behind after a failed pull"

if $java; then
	echo "== --java: a JVM's own TLS, in a pod running as another user"
	cat > "$tmp/Loop.java" <<'JAVA'
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

// Requests https://tls-server/ every second through java.net.http, which
// is SunJSSE's SSLEngine, trusting the server's certificate of its own
// making (or any).
public class Loop {
    public static void main(String[] args) throws Exception {
        TrustManager any = new X509ExtendedTrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public void checkClientTrusted(X509Certificate[] c, String a, Socket s) {}
            public void checkServerTrusted(X509Certificate[] c, String a, Socket s) {}
            public void checkClientTrusted(X509Certificate[] c, String a, SSLEngine e) {}
            public void checkServerTrusted(X509Certificate[] c, String a, SSLEngine e) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };
        SSLContext tls = SSLContext.getInstance("TLS");
        tls.init(null, new TrustManager[] {any}, null);
        HttpClient c = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).sslContext(tls).build();
        boolean said = false;
        while (true) {
            try {
                c.send(HttpRequest.newBuilder(URI.create("https://tls-server/")).build(), HttpResponse.BodyHandlers.discarding());
                if (!said) {
                    System.out.println("requesting");
                    said = true;
                }
            } catch (Exception e) {
                System.err.println(e);
            }
            Thread.sleep(1000);
        }
    }
}
JAVA
	k create configmap javaclient --from-file="$tmp/Loop.java" >/dev/null
	k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: javaclient
spec:
  securityContext:
    runAsUser: 65534
    runAsGroup: 65534
  containers:
    - name: java
      image: $java_image
      command: [java, /src/Loop.java]
      volumeMounts:
        - { name: src, mountPath: /src }
  volumes:
    - name: src
      configMap: { name: javaclient }
YAML
	k wait --for=condition=Ready pod/javaclient --timeout=300s >/dev/null
	# The JVM compiling Loop.java and getting going: it says when it has.
	until_ok 120 sh -c 'kubectl -n "$0" logs javaclient | grep -q requesting' "$ns" || fail "the Java client made no requests"
	status=0
	timeout 180 "$tmp/kubectl-snoopy" -n "$ns" javaclient --image "$image" --java --json --count 4 > "$tmp/out.json" 2> "$tmp/err" || status=$?
	if [ "$status" -ne 0 ]; then
		cat "$tmp/err" >&2
		fail "kubectl snoopy --java exited with $status"
	fi
	grep -v '^{' "$tmp/err" || true
	engine=$(grep -c '"function":"SSLEngine' "$tmp/out.json" || true)
	named=$(grep '"function":"SSLEngine' "$tmp/out.json" | grep -c '"container_name":"javaclient/java"' || true)
	echo "SSLEngine events: $engine, named javaclient/java: $named"
	[ "$engine" -ge 4 ] || fail "expected 4 SSLEngine events"
	[ "$named" -eq "$engine" ] || fail "SSLEngine events without the pod's container name"
	k delete pod javaclient --wait=false >/dev/null
fi

echo "== a namespace that doesn't allow privileged pods"
kubectl create namespace "$ns-restricted" >/dev/null
kubectl label namespace "$ns-restricted" pod-security.kubernetes.io/enforce=baseline --overwrite >/dev/null
if snoopy client --debug-namespace "$ns-restricted" --count 1 > /dev/null 2> "$tmp/err"; then
	fail "the snoopy pod was created in a baseline namespace"
fi
grep -q -- "--debug-namespace" "$tmp/err" || { cat "$tmp/err" >&2; fail "no advice about --debug-namespace"; }
echo "explained: $(head -1 "$tmp/err" | cut -c1-100)"

echo PASS
