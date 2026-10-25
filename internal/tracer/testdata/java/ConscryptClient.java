import java.net.URI;
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import org.conscrypt.Conscrypt;

// ConscryptClient URL DELAY_MS: a GET of URL through HttpsURLConnection with
// Conscrypt as the TLS provider, which loads it, DELAY_MS after starting.
public class ConscryptClient {
	public static void main(String[] args) throws Exception {
		Thread.sleep(Long.parseLong(args[1]));
		Security.insertProviderAt(Conscrypt.newProvider(), 1);
		TrustManager[] trustAll = {new X509TrustManager() {
			public void checkClientTrusted(X509Certificate[] c, String a) {}
			public void checkServerTrusted(X509Certificate[] c, String a) {}
			public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
		}};
		SSLContext ctx = SSLContext.getInstance("TLS", "Conscrypt");
		ctx.init(null, trustAll, null);
		HttpsURLConnection c = (HttpsURLConnection) URI.create(args[0]).toURL().openConnection();
		c.setSSLSocketFactory(ctx.getSocketFactory());
		c.setHostnameVerifier((h, s) -> true);
		System.out.println(new String(c.getInputStream().readAllBytes()));
	}
}
