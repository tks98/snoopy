package snoopy.hooks;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * What the instrumented JSSE methods call, loaded by the bootstrap class
 * loader so java.base can see it. Each call copies the application bytes of
 * a TLS read or write into a frame written to a descriptor for /dev/null,
 * where snoopy's write tracepoint reads it. Nothing here may throw into the
 * application.
 *
 * Spike: the frame format and its registration are not final (see
 * docs/plan-java.md).
 */
public final class Hooks {
    private Hooks() {}

    /** "SNPYJV01", the frame's first eight bytes. */
    public static final long MAGIC = 0x3130564a59504e53L;
    public static final int HEADER = 88; // struct java_frame in bpf/snoopy.c
    static final byte WRITE = 0, READ = 1;
    static final byte SOCKET = 0, ENGINE = 1;
    static final int AF_INET = 2, AF_INET6 = 10;

    static volatile boolean enabled;
    static volatile int maxCapture = 16384;
    static long nonce;
    static FileOutputStream out;
    static final AtomicLong seq = new AtomicLong();
    static final AtomicLong failed = new AtomicLong();
    static final AtomicLong nextConn = new AtomicLong(1);
    static final Map<Object, Long> conns = new WeakHashMap<>();

    /** Opens the transport and starts copying; true if it's ready. */
    public static synchronized boolean enable(long sessionNonce, int max) {
        try {
            if (out == null) {
                out = new FileOutputStream("/dev/null");
            }
            nonce = sessionNonce;
            maxCapture = max;
            enabled = true;
            Runtime.getRuntime().addShutdownHook(new Thread(() -> System.err.println(
                    "snoopy agent: " + seq.get() + " frames, " + failed.get() + " not written")));
            // A frame with no payload says the transport is ready.
            emit(0, WRITE, SOCKET, null, 0, 0, 0, null, 0);
            return true;
        } catch (Throwable t) {
            enabled = false;
            return false;
        }
    }

    public static void disable() {
        enabled = false;
    }

    /** The transport's descriptor number, for registering it (spike: by reflection). */
    public static int fd() {
        try {
            FileDescriptor d = out.getFD();
            var f = FileDescriptor.class.getDeclaredField("fd");
            f.setAccessible(true);
            return f.getInt(d);
        } catch (Throwable t) {
            return -1;
        }
    }

    static long conn(Object owner) {
        synchronized (conns) {
            Long id = conns.get(owner);
            if (id == null) {
                id = nextConn.getAndIncrement();
                conns.put(owner, id);
            }
            return id;
        }
    }

    // SSLSocketImpl$AppOutputStream.write(byte[], int, int), on return.
    public static void socketWrite(Object socket, byte[] b, int off, int len, long start) {
        if (!enabled || len <= 0) {
            return;
        }
        try {
            socketFrame(socket, WRITE, b, off, len, start);
        } catch (Throwable t) {
            // never into the application
        }
    }

    // SSLSocketImpl$AppInputStream.read(byte[], int, int), on return, with
    // what it returned.
    public static void socketRead(Object socket, byte[] b, int off, int n, long start) {
        if (!enabled || n <= 0) {
            return;
        }
        try {
            socketFrame(socket, READ, b, off, n, start);
        } catch (Throwable t) {
            // never into the application
        }
    }

    static void socketFrame(Object socket, byte dir, byte[] b, int off, int len, long start) {
        emit(conn(socket), dir, SOCKET, b, off, len, len, socket instanceof Socket s ? s : null, System.nanoTime() - start);
    }

    /**
     * SSLEngineImpl.wrap and unwrap's entry: the positions of the buffers
     * whose application bytes they consume (wrap's sources) or produce
     * (unwrap's destinations).
     */
    public static int[] positions(ByteBuffer[] bufs, int off, int len) {
        if (!enabled || bufs == null) {
            return null;
        }
        try {
            int[] pos = new int[len];
            for (int i = 0; i < len; i++) {
                pos[i] = bufs[off + i].position();
            }
            return pos;
        } catch (Throwable t) {
            return null;
        }
    }

    // SSLEngineImpl.wrap(ByteBuffer[], int, int, ByteBuffer[], int, int), on
    // return: the sources' bytes it consumed.
    public static void engineWrap(Object engine, javax.net.ssl.SSLEngineResult r, ByteBuffer[] srcs, int off, int len, int[] pos, long start) {
        if (!enabled || r == null || pos == null || r.bytesConsumed() <= 0) {
            return;
        }
        try {
            engineFrame(engine, WRITE, r.bytesConsumed(), srcs, off, len, pos, start);
        } catch (Throwable t) {
            // never into the application
        }
    }

    // SSLEngineImpl.unwrap(ByteBuffer[], int, int, ByteBuffer[], int, int),
    // on return: the bytes it produced into the destinations.
    public static void engineUnwrap(Object engine, javax.net.ssl.SSLEngineResult r, ByteBuffer[] dsts, int off, int len, int[] pos, long start) {
        if (!enabled || r == null || pos == null || r.bytesProduced() <= 0) {
            return;
        }
        try {
            engineFrame(engine, READ, r.bytesProduced(), dsts, off, len, pos, start);
        } catch (Throwable t) {
            // never into the application
        }
    }

    // engineFrame gathers n bytes from bufs, from the positions they had at
    // entry, without moving them.
    static void engineFrame(Object engine, byte dir, int n, ByteBuffer[] bufs, int off, int len, int[] pos, long start) {
        int cap = Math.min(n, maxCapture);
        byte[] data = new byte[cap];
        int got = 0;
        for (int i = 0; i < len && got < cap; i++) {
            ByteBuffer d = bufs[off + i].duplicate();
            int end = d.position(); // consumed or produced up to here
            int from = pos[i];
            int k = Math.min(end - from, cap - got);
            if (k <= 0) {
                continue;
            }
            d.limit(from + k).position(from);
            d.get(data, got, k);
            got += k;
        }
        emit(conn(engine), dir, ENGINE, data, 0, got, n, null, System.nanoTime() - start);
    }

    // emit writes one frame: the header (struct java_frame), then up to
    // maxCapture bytes of the payload. Synchronized, so frames keep their
    // order and aren't torn.
    static synchronized void emit(long conn, byte dir, byte kind, byte[] b, int off, int len, int orig, Socket socket, long latency) {
        int cap = Math.min(len, maxCapture);
        byte[] frame = new byte[HEADER + cap];
        ByteBuffer h = ByteBuffer.wrap(frame).order(ByteOrder.LITTLE_ENDIAN);
        h.putLong(MAGIC).putLong(nonce).putLong(conn).putLong(seq.getAndIncrement());
        InetAddress local = socket == null ? null : socket.getLocalAddress();
        InetAddress remote = socket == null ? null : socket.getInetAddress();
        int family = 0;
        if (local != null && remote != null && local.getClass() == remote.getClass()) {
            family = remote instanceof Inet4Address ? AF_INET : AF_INET6;
        }
        h.put(dir).put(kind).putShort((short) family);
        h.putInt(orig).putInt(cap);
        h.putShort((short) (family == 0 ? 0 : socket.getLocalPort())).putShort((short) (family == 0 ? 0 : socket.getPort()));
        if (family != 0) {
            h.put(local.getAddress()).position(64).put(remote.getAddress());
        }
        h.position(80).putLong(Math.max(latency, 0));
        if (cap > 0) {
            System.arraycopy(b, off, frame, HEADER, cap);
        }
        try {
            out.write(frame);
        } catch (Throwable t) {
            failed.incrementAndGet();
        }
    }
}
