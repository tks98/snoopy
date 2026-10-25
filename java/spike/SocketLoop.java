import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

// Spike client for SSLSocket: every delay_ms, for n rounds, POSTs to
// https://127.0.0.1:port/sock/<i> on a new connection, and prints what it
// wrote and read, in hex, as "W <hex>" and "R <hex>" lines.
//   java SocketLoop.java PORT N DELAY_MS [WARM]
public class SocketLoop {
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
        HexFormat hex = HexFormat.of();
        for (int i = -warm; i < n; i++) {
            if (i >= 0) Thread.sleep(delay);
            try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket("127.0.0.1", port)) {
                String body = "socket-body-" + i + "-" + "x".repeat(Math.max(i, 0) * 100);
                byte[] req = ("POST /sock/" + i + " HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: " + body.length()
                        + "\r\nConnection: close\r\n\r\n" + body).getBytes(StandardCharsets.US_ASCII);
                OutputStream out = s.getOutputStream();
                out.write(req);
                out.flush();
                if (i >= 0) System.out.println("W " + hex.formatHex(req));
                InputStream in = s.getInputStream();
                ByteArrayOutputStream got = new ByteArrayOutputStream();
                byte[] buf = new byte[512]; // small, so reads come in pieces
                for (int k; (k = in.read(buf, 0, buf.length)) > 0; ) {
                    got.write(buf, 0, k);
                }
                if (i >= 0) System.out.println("R " + hex.formatHex(got.toByteArray()));
            }
        }
    }
}
