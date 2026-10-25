import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

// For TestJSSE: POSTs to URL/jsse/MODE/<i> through SunJSSE, MODE "socket"
// (an SSLSocket) or "engine" (java.net.http.HttpClient, on SSLEngine), with
// a body of BODY bytes. It makes WARM requests first, prints "ready", waits
// for a line on stdin (the agent is loaded in between), then makes N more,
// printing "served" with each response.
//   java JSSEClient.java URL MODE BODY WARM N
public class JSSEClient {
    public static void main(String[] args) throws Exception {
        URI base = URI.create(args[0]);
        String mode = args[1];
        int body = Integer.parseInt(args[2]), warm = Integer.parseInt(args[3]), n = Integer.parseInt(args[4]);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        HttpClient client = HttpClient.newBuilder().sslContext(ctx).version(HttpClient.Version.HTTP_1_1).build();
        for (int i = -warm; i < n; i++) {
            if (i == 0) {
                System.out.println("ready");
                System.out.flush();
                new BufferedReader(new InputStreamReader(System.in)).readLine();
            }
            String path = "/jsse/" + mode + "/" + (i < 0 ? "warm" : String.valueOf(i));
            String data = "jsse-body-" + "z".repeat(Math.max(body - 10, 0));
            String got;
            if (mode.equals("socket")) {
                try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(base.getHost(), base.getPort())) {
                    OutputStream out = s.getOutputStream();
                    out.write(("POST " + path + " HTTP/1.1\r\nHost: " + base.getAuthority() + "\r\nContent-Length: " + data.length()
                            + "\r\nConnection: close\r\n\r\n" + data).getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                    InputStream in = s.getInputStream();
                    ByteArrayOutputStream resp = new ByteArrayOutputStream();
                    in.transferTo(resp);
                    got = resp.toString(StandardCharsets.US_ASCII);
                }
            } else {
                HttpRequest req = HttpRequest.newBuilder(base.resolve(path)).POST(HttpRequest.BodyPublishers.ofString(data)).build();
                got = client.send(req, HttpResponse.BodyHandlers.ofString()).body();
            }
            if (i >= 0) {
                System.out.println(got.substring(Math.max(got.indexOf("served"), 0)));
            }
        }
    }
}
