import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

// For TestJSSE: a client and a server SSLEngine in one JVM, connected in
// memory, with no socket. After the handshake it waits for a line on stdin
// (the agent is loaded in between), then the client wraps one message from
// each kind of source buffer, and the server unwraps each into a different
// kind of destination. It prints each message as "msg <text>".
//   java EngineBuffers.java KEYSTORE.p12 PASSWORD
public class EngineBuffers {
    static SSLEngine client, server;
    static ByteBuffer toServer = ByteBuffer.allocate(1 << 17), toClient = ByteBuffer.allocate(1 << 17);

    public static void main(String[] args) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(args[0])) {
            ks.load(in, args[1].toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, args[1].toCharArray());
        SSLContext serverCtx = SSLContext.getInstance("TLS");
        serverCtx.init(kmf.getKeyManagers(), null, null);
        SSLContext clientCtx = SSLContext.getInstance("TLS");
        clientCtx.init(null, new TrustManager[] {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);
        client = clientCtx.createSSLEngine("localhost", 443);
        client.setUseClientMode(true);
        server = serverCtx.createSSLEngine();
        server.setUseClientMode(false);
        client.beginHandshake();
        server.beginHandshake();
        handshake();

        System.out.println("ready");
        System.out.flush();
        new BufferedReader(new InputStreamReader(System.in)).readLine();

        String[] kinds = {"heap", "direct", "sliced", "read-only", "gathered", "large"};
        String[] dstKinds = {"heap", "direct", "offset", "scattered", "heap", "heap"};
        for (int i = 0; i < kinds.length; i++) {
            String text = "engine-buffers-" + kinds[i] + "-into-" + dstKinds[i] + "-" + "q".repeat(i == 5 ? 30000 : 20 * i);
            byte[] msg = text.getBytes(StandardCharsets.US_ASCII);
            ByteBuffer[] srcs = sources(kinds[i], msg);
            // A wrap with no room for a record consumes nothing: no event.
            if (client.wrap(srcs, ByteBuffer.allocate(16)).bytesConsumed() != 0) {
                throw new IllegalStateException("consumed into 16 bytes");
            }
            int sent = 0;
            while (sent < msg.length) {
                SSLEngineResult r = client.wrap(srcs, toServer);
                check(r);
                sent += r.bytesConsumed();
            }
            toServer.flip();
            String got = unwrapAll(dstKinds[i], msg.length);
            toServer.compact();
            if (!got.equals(text)) {
                throw new IllegalStateException("got " + got.length() + " bytes back, not " + text.length());
            }
            System.out.println("msg " + text.substring(0, Math.min(text.length(), 60)));
        }
    }

    static ByteBuffer[] sources(String kind, byte[] msg) {
        switch (kind) {
            case "direct": {
                ByteBuffer b = ByteBuffer.allocateDirect(msg.length);
                b.put(msg).flip();
                return new ByteBuffer[] {b};
            }
            case "sliced": {
                ByteBuffer b = ByteBuffer.allocate(msg.length + 100);
                b.position(37);
                ByteBuffer s = b.slice();
                s.put(msg).flip();
                return new ByteBuffer[] {s};
            }
            case "read-only":
                return new ByteBuffer[] {ByteBuffer.wrap(msg).asReadOnlyBuffer()};
            case "gathered": {
                int half = msg.length / 2;
                return new ByteBuffer[] {ByteBuffer.wrap(msg, 0, half), ByteBuffer.wrap(msg, half, msg.length - half)};
            }
            default:
                return new ByteBuffer[] {ByteBuffer.wrap(msg)};
        }
    }

    // unwrapAll unwraps what the client sent into destinations of a kind,
    // and returns what came out.
    static String unwrapAll(String kind, int n) throws Exception {
        StringBuilder got = new StringBuilder();
        while (got.length() < n && toServer.hasRemaining()) {
            ByteBuffer[] dsts;
            switch (kind) {
                case "direct":
                    dsts = new ByteBuffer[] {ByteBuffer.allocateDirect(1 << 15)};
                    break;
                case "offset": {
                    ByteBuffer b = ByteBuffer.allocate(1 << 15);
                    b.position(11);
                    dsts = new ByteBuffer[] {b};
                    break;
                }
                case "scattered":
                    dsts = new ByteBuffer[] {ByteBuffer.allocate(9), ByteBuffer.allocate(1 << 15)};
                    break;
                default:
                    dsts = new ByteBuffer[] {ByteBuffer.allocate(1 << 15)};
            }
            int[] start = new int[dsts.length];
            for (int i = 0; i < dsts.length; i++) {
                start[i] = dsts[i].position();
            }
            SSLEngineResult r = server.unwrap(toServer, dsts);
            check(r);
            for (int i = 0; i < dsts.length; i++) {
                ByteBuffer d = dsts[i].duplicate();
                d.flip().position(start[i]);
                byte[] b = new byte[d.remaining()];
                d.get(b);
                got.append(new String(b, StandardCharsets.US_ASCII));
            }
        }
        return got.toString();
    }

    static void check(SSLEngineResult r) {
        if (r.getStatus() != SSLEngineResult.Status.OK) {
            throw new IllegalStateException("engine: " + r);
        }
    }

    static void handshake() throws Exception {
        ByteBuffer empty = ByteBuffer.allocate(0), sink = ByteBuffer.allocate(1 << 15);
        for (int i = 0; i < 1000; i++) {
            boolean done = true;
            for (SSLEngine e : new SSLEngine[] {client, server}) {
                ByteBuffer out = e == client ? toServer : toClient, in = e == client ? toClient : toServer;
                switch (e.getHandshakeStatus()) {
                    case NEED_WRAP:
                        e.wrap(empty, out);
                        done = false;
                        break;
                    case NEED_UNWRAP:
                        in.flip();
                        e.unwrap(in, sink);
                        in.compact();
                        sink.clear();
                        done = false;
                        break;
                    case NEED_TASK:
                        for (Runnable t; (t = e.getDelegatedTask()) != null; ) t.run();
                        done = false;
                        break;
                    default:
                }
            }
            if (done) {
                return;
            }
        }
        throw new IllegalStateException("handshake didn't finish");
    }
}
