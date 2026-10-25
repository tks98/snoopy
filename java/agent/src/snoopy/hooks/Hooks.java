package snoopy.hooks;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReferenceArray;

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

    /** Opens the transport and starts copying; true if it's ready. */
    public static synchronized boolean enable(long sessionNonce, int max) {
        try {
            if (out == null) {
                out = new FileOutputStream("/dev/null");
            }
            nonce = sessionNonce;
            maxCapture = max;
            enabled = true;
            // A frame with no payload says the transport is ready.
            byte[] f = new byte[HEADER];
            header(f, null, WRITE, SOCKET, 0, 0, 0);
            emit(null, f, HEADER);
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

    // A connection: the agent's ID for it, and what its frames' headers say
    // of its addresses.
    static final class Conn {
        final WeakReference<Object> owner;
        final long id;
        final short family, lport, rport;
        final byte[] laddr, raddr;

        Conn(Object owner, long id) {
            this.owner = new WeakReference<>(owner);
            this.id = id;
            short f = 0, lp = 0, rp = 0;
            byte[] la = null, ra = null;
            if (owner instanceof Socket s) {
                InetAddress local = s.getLocalAddress(), remote = s.getInetAddress();
                if (local != null && remote != null && local.getClass() == remote.getClass()) {
                    f = (short) (remote instanceof Inet4Address ? AF_INET : AF_INET6);
                    la = local.getAddress();
                    ra = remote.getAddress();
                    lp = (short) s.getLocalPort();
                    rp = (short) s.getPort();
                }
            }
            family = f;
            lport = lp;
            rport = rp;
            laddr = la;
            raddr = ra;
        }
    }

    static final Map<Object, Conn> conns = new WeakHashMap<>();
    // The connections seen last, by identity hash: most calls find theirs
    // here, without a lock.
    static final AtomicReferenceArray<Conn> recent = new AtomicReferenceArray<>(256);

    static Conn conn(Object owner) {
        int slot = System.identityHashCode(owner) & (recent.length() - 1);
        Conn c = recent.get(slot);
        if (c != null && c.owner.get() == owner) {
            return c;
        }
        synchronized (conns) {
            c = conns.get(owner);
            if (c == null) {
                c = new Conn(owner, nextConn.getAndIncrement());
                conns.put(owner, c);
            }
        }
        recent.set(slot, c);
        return c;
    }

    // Frames are built in arrays kept here between calls, one per slot,
    // which threads (virtual ones too) take turns with.
    static final AtomicReferenceArray<byte[]> frames = new AtomicReferenceArray<>(64);

    static byte[] takeFrame(int size) {
        int slot = (int) Thread.currentThread().getId() & (frames.length() - 1);
        byte[] f = frames.getAndSet(slot, null);
        return f != null && f.length >= size ? f : new byte[Math.max(size, HEADER + 2048)];
    }

    static void giveFrame(byte[] f) {
        int slot = (int) Thread.currentThread().getId() & (frames.length() - 1);
        if (f.length <= HEADER + maxCapture) {
            frames.compareAndSet(slot, null, f);
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
        Conn c = conn(socket);
        int cap = Math.min(len, maxCapture);
        byte[] f = takeFrame(HEADER + cap);
        header(f, c, dir, SOCKET, len, cap, System.nanoTime() - start);
        System.arraycopy(b, off, f, HEADER, cap);
        emit(c, f, HEADER + cap);
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
    // entry, into a frame, without moving them.
    static void engineFrame(Object engine, byte dir, int n, ByteBuffer[] bufs, int off, int len, int[] pos, long start) {
        Conn c = conn(engine);
        int cap = Math.min(n, maxCapture);
        byte[] f = takeFrame(HEADER + cap);
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
            d.get(f, HEADER + got, k);
            got += k;
        }
        header(f, c, dir, ENGINE, n, got, System.nanoTime() - start);
        emit(c, f, HEADER + got);
    }

    // header fills in a frame's header, struct java_frame.
    static void header(byte[] f, Conn c, byte dir, byte kind, int size, int captured, long latency) {
        ByteBuffer h = ByteBuffer.wrap(f, 0, HEADER).order(ByteOrder.LITTLE_ENDIAN);
        h.putLong(MAGIC).putLong(nonce).putLong(c == null ? 0 : c.id).putLong(0); // seq: set in emit
        h.put(dir).put(kind).putShort(c == null ? 0 : c.family);
        h.putInt(size).putInt(captured);
        h.putShort(c == null ? 0 : c.lport).putShort(c == null ? 0 : c.rport);
        Arrays.fill(f, 48, 80, (byte) 0); // a reused frame's addresses
        if (c != null && c.family != 0) {
            h.put(c.laddr).position(64).put(c.raddr);
        }
        h.position(80).putLong(Math.max(latency, 0));
    }

    // emit writes a frame of n bytes and gives it back. A connection's
    // frames are written one at a time, in order; /dev/null writes are
    // atomic, so different connections' go at once.
    static void emit(Conn c, byte[] f, int n) {
        Object lock = c == null ? Hooks.class : c;
        try {
            synchronized (lock) {
                ByteBuffer.wrap(f, 24, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(seq.getAndIncrement());
                out.write(f, 0, n);
            }
        } catch (Throwable t) {
            failed.incrementAndGet();
        } finally {
            giveFrame(f);
        }
    }
}
