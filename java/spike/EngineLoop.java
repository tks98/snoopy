import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

// Spike client for SSLEngine, through java.net.http.HttpClient over
// HTTP/1.1: every delay_ms, for n rounds, POSTs to /engine/<i> and prints
// the request and response bodies in hex as "WB <hex>" and "RB <hex>".
//   java EngineLoop.java PORT N DELAY_MS [WARM]
public class EngineLoop {
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(args[0]), n = Integer.parseInt(args[1]);
        long delay = Long.parseLong(args[2]);
        int warm = args.length > 3 ? Integer.parseInt(args[3]) : 0; // rounds first, unprinted and undelayed
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        HttpClient c = HttpClient.newBuilder().sslContext(ctx).version(HttpClient.Version.HTTP_1_1).build();
        HexFormat hex = HexFormat.of();
        for (int i = -warm; i < n; i++) {
            if (i >= 0) Thread.sleep(delay);
            String body = "engine-body-" + i + "-" + "y".repeat(Math.max(i, 0) * 100);
            HttpRequest req = HttpRequest.newBuilder(URI.create("https://127.0.0.1:" + port + "/engine/" + i))
                    .POST(HttpRequest.BodyPublishers.ofString(body)).build();
            HttpResponse<byte[]> resp = c.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (i >= 0) System.out.println("WB " + hex.formatHex(body.getBytes(StandardCharsets.US_ASCII)));
            if (i >= 0) System.out.println("RB " + hex.formatHex(resp.body()));
        }
    }
}
