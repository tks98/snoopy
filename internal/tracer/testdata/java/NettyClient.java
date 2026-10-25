import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.*;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;

// NettyClient URL DELAY_MS: a GET of URL over Netty with netty-tcnative's
// BoringSSL (SslProvider.OPENSSL), which loads it, DELAY_MS after starting.
public class NettyClient {
	public static void main(String[] args) throws Exception {
		URI u = URI.create(args[0]);
		Thread.sleep(Long.parseLong(args[1]));
		if (!OpenSsl.isAvailable()) {
			throw OpenSsl.unavailabilityCause() == null ? new IllegalStateException("no netty-tcnative") : new IllegalStateException(OpenSsl.unavailabilityCause());
		}
		SslContext ctx = SslContextBuilder.forClient().sslProvider(SslProvider.OPENSSL)
			.trustManager(InsecureTrustManagerFactory.INSTANCE).build();
		CountDownLatch done = new CountDownLatch(1);
		NioEventLoopGroup group = new NioEventLoopGroup(1);
		try {
			Channel ch = new Bootstrap().group(group).channel(NioSocketChannel.class).handler(new ChannelInitializer<Channel>() {
				protected void initChannel(Channel c) {
					c.pipeline().addLast(ctx.newHandler(c.alloc(), u.getHost(), u.getPort()));
					c.pipeline().addLast(new SimpleChannelInboundHandler<ByteBuf>() {
						protected void channelRead0(ChannelHandlerContext x, ByteBuf b) {
							System.out.print(b.toString(StandardCharsets.US_ASCII));
						}
						public void channelInactive(ChannelHandlerContext x) { done.countDown(); }
					});
				}
			}).connect(u.getHost(), u.getPort()).sync().channel();
			String req = "GET " + u.getPath() + " HTTP/1.1\r\nHost: " + u.getHost() + "\r\nConnection: close\r\n\r\n";
			ch.writeAndFlush(Unpooled.copiedBuffer(req, StandardCharsets.US_ASCII)).sync();
			done.await();
		} finally {
			group.shutdownGracefully().sync();
		}
	}
}
