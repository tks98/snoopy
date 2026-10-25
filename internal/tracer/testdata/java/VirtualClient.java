import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

// For TestJSSE (JDK 21 and later): N SSLSocket connections at once, each on
// a virtual thread, POSTing to URL/jsse/virtual/<i> in several writes, so
// that calls of different connections interleave. It prints "ready", waits
// for a line on stdin, then prints "served" for each.
//   java VirtualClient.java URL N
public class VirtualClient {
    public static void main(String[] args) throws Exception {
        URI base = URI.create(args[0]);
        int n = Integer.parseInt(args[1]);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);
        System.out.println("ready");
        System.out.flush();
        new BufferedReader(new InputStreamReader(System.in)).readLine();
        try (ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<String>> results = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                int id = i;
                results.add(ex.submit(() -> {
                    try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(base.getHost(), base.getPort())) {
                        String body = ("virtual-" + id + "-").repeat(50);
                        OutputStream out = s.getOutputStream();
                        out.write(("POST /jsse/virtual/" + id + " HTTP/1.1\r\nHost: " + base.getAuthority() + "\r\nContent-Length: "
                                + body.length() + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                        for (int k = 0; k < body.length(); k += 100) { // in pieces, yielding between
                            out.write(body.substring(k, Math.min(k + 100, body.length())).getBytes(StandardCharsets.US_ASCII));
                            Thread.yield();
                        }
                        out.flush();
                        ByteArrayOutputStream resp = new ByteArrayOutputStream();
                        s.getInputStream().transferTo(resp);
                        String got = resp.toString(StandardCharsets.US_ASCII);
                        return got.substring(Math.max(got.indexOf("served"), 0));
                    }
                }));
            }
            for (Future<String> f : results) {
                System.out.println(f.get());
            }
        }
    }
}
