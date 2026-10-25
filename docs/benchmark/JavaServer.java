import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.util.concurrent.Executors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

// The JSSE server for docs/benchmark/java.sh: the JDK's own HTTPS server
// (on SSLEngine), answering /1k and /256k with that many bytes.
//   java JavaServer.java PORT KEYSTORE.p12 PASSWORD THREADS
public class JavaServer {
    public static void main(String[] args) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream in = new FileInputStream(args[1])) {
            ks.load(in, args[2].toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, args[2].toCharArray());
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        HttpsServer srv = HttpsServer.create(new InetSocketAddress("127.0.0.1", Integer.parseInt(args[0])), 1024);
        srv.setHttpsConfigurator(new HttpsConfigurator(ctx));
        srv.setExecutor(Executors.newFixedThreadPool(Integer.parseInt(args[3])));
        for (int size : new int[] {1024, 262144}) {
            byte[] body = "a".repeat(size).getBytes();
            srv.createContext(size == 1024 ? "/1k" : "/256k", ex -> {
                ex.sendResponseHeaders(200, body.length);
                try (OutputStream out = ex.getResponseBody()) {
                    out.write(body);
                }
            });
        }
        srv.start();
        System.out.println("ready");
    }
}
