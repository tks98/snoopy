package snoopy.agent;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;

/**
 * snoopy's Java agent: instruments SunJSSE's application data paths
 * to call snoopy.hooks.Hooks, which the manifest's Boot-Class-Path puts in
 * the bootstrap class loader. Loaded at startup (-javaagent) or into a
 * running JVM (the attach mechanism); options are nonce=N,max=N.
 */
public final class Agent {
    private Agent() {}

    static final String HOOKS = "snoopy/hooks/Hooks";
    static final String SOCKET_IN = "sun/security/ssl/SSLSocketImpl$AppInputStream";
    static final String SOCKET_OUT = "sun/security/ssl/SSLSocketImpl$AppOutputStream";
    static final String ENGINE = "sun/security/ssl/SSLEngineImpl";
    static final String BUFS = "([Ljava/nio/ByteBuffer;II[Ljava/nio/ByteBuffer;II)Ljavax/net/ssl/SSLEngineResult;";
    static final Set<String> TARGETS = Set.of(SOCKET_IN, SOCKET_OUT, ENGINE);

    public static void premain(String args, Instrumentation inst) throws Exception {
        start(args, inst);
    }

    public static void agentmain(String args, Instrumentation inst) throws Exception {
        start(args, inst);
    }

    // Whether the transformer is in: a JVM keeps the agent's classes when
    // it's loaded again (by a later snoopy), and this once loaded.
    static boolean installed;

    // Options: nonce=N (the session's, unsigned), max=N (bytes captured per
    // call), or disable, which stops capturing (the instrumentation stays,
    // doing nothing, until the JVM exits).
    static synchronized void start(String args, Instrumentation inst) throws Exception {
        long nonce = 0;
        int max = 16384;
        boolean disable = false;
        if (args != null) {
            for (String kv : args.split(",")) {
                String[] p = kv.split("=", 2);
                if (p.length == 2 && p[0].equals("nonce")) nonce = Long.parseUnsignedLong(p[1]);
                if (p.length == 2 && p[0].equals("max")) max = Integer.parseInt(p[1]);
                if (p[0].equals("disable")) disable = true;
            }
        }
        // Hooks is the bootstrap loader's; java.base has to read its module
        // to call it.
        Class<?> hooks = Class.forName("snoopy.hooks.Hooks", true, null);
        if (disable) {
            hooks.getMethod("disable").invoke(null);
            return;
        }
        if (!installed) {
            Module base = Object.class.getModule();
            inst.redefineModule(base, Set.of(hooks.getModule()), Map.of(), Map.of(), Set.of(), Map.of());
            inst.addTransformer(new Transformer(), true);
            List<Class<?>> loaded = new ArrayList<>();
            for (Class<?> c : inst.getAllLoadedClasses()) {
                if (TARGETS.contains(c.getName().replace('.', '/'))) {
                    loaded.add(c);
                }
            }
            if (!loaded.isEmpty()) {
                inst.retransformClasses(loaded.toArray(new Class<?>[0]));
            }
            installed = true;
        }
        if (!(boolean) hooks.getMethod("enable", long.class, int.class).invoke(null, nonce, max)) {
            // The load succeeds, but no ready frame comes: snoopy says so.
            System.err.println("snoopy agent: can't open /dev/null, so nothing is captured");
        }
    }

    static final class Transformer implements ClassFileTransformer {
        @Override
        public byte[] transform(Module module, ClassLoader loader, String name, Class<?> redefined,
                ProtectionDomain pd, byte[] classfile) {
            if (loader != null || !TARGETS.contains(name)) {
                return null;
            }
            try {
                ClassReader r = new ClassReader(classfile);
                // No COMPUTE_FRAMES: it loads classes, which mustn't happen
                // while a JDK class is being defined; the added code has no
                // branches, so the existing frames stay right.
                ClassWriter w = new ClassWriter(r, ClassWriter.COMPUTE_MAXS);
                r.accept(new Visitor(w, name), ClassReader.EXPAND_FRAMES);
                return w.toByteArray();
            } catch (Throwable t) {
                System.err.println("snoopy agent: not instrumenting " + name + ": " + t);
                return null;
            }
        }
    }

    static final class Visitor extends ClassVisitor {
        final String owner;

        Visitor(ClassVisitor cv, String owner) {
            super(Opcodes.ASM9, cv);
            this.owner = owner;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc, String sig, String[] exc) {
            MethodVisitor mv = super.visitMethod(access, name, desc, sig, exc);
            if (owner.equals(SOCKET_OUT) && name.equals("write") && desc.equals("([BII)V")) {
                return new SocketAdvice(mv, access, name, desc, owner, false);
            }
            if (owner.equals(SOCKET_IN) && name.equals("read") && desc.equals("([BII)I")) {
                return new SocketAdvice(mv, access, name, desc, owner, true);
            }
            if (owner.equals(ENGINE) && desc.equals(BUFS) && (name.equals("wrap") || name.equals("unwrap"))) {
                return new EngineAdvice(mv, access, name, desc, name.equals("wrap"));
            }
            return mv;
        }
    }

    // On a normal return, passes the owning socket and the buffer's range
    // (as called; for a read, as many bytes as it returned) to Hooks.
    static final class SocketAdvice extends AdviceAdapter {
        final String owner;
        final boolean read;
        int buf, off, len, n, start;

        SocketAdvice(MethodVisitor mv, int access, String name, String desc, String owner, boolean read) {
            super(Opcodes.ASM9, mv, access, name, desc);
            this.owner = owner;
            this.read = read;
        }

        @Override
        protected void onMethodEnter() {
            // The arguments as called, in case the method reassigns them.
            buf = newLocal(Type.getType("[B"));
            off = newLocal(Type.INT_TYPE);
            len = newLocal(Type.INT_TYPE);
            n = newLocal(Type.INT_TYPE);
            loadArg(0);
            storeLocal(buf);
            loadArg(1);
            storeLocal(off);
            loadArg(2);
            storeLocal(len);
            push(0);
            storeLocal(n);
            start = newLocal(Type.LONG_TYPE);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "nanoTime", "()J", false);
            storeLocal(start);
        }

        @Override
        protected void onMethodExit(int opcode) {
            if (opcode == ATHROW) {
                return;
            }
            if (read) {
                dup(); // the count returned, which stays the return value
                storeLocal(n);
            }
            loadThis();
            getField(Type.getObjectType(owner), "this$0", Type.getObjectType("sun/security/ssl/SSLSocketImpl"));
            loadLocal(buf);
            loadLocal(off);
            loadLocal(read ? n : len);
            loadLocal(start);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, read ? "socketRead" : "socketWrite",
                    "(Ljava/lang/Object;[BIIJ)V", false);
        }
    }

    // Saves the application buffers' positions at entry, and on a normal
    // return passes them with the result to Hooks.
    static final class EngineAdvice extends AdviceAdapter {
        final boolean wrap;
        int pos, start;

        EngineAdvice(MethodVisitor mv, int access, String name, String desc, boolean wrap) {
            super(Opcodes.ASM9, mv, access, name, desc);
            this.wrap = wrap;
        }

        // wrap's application data is its sources (arguments 0-2), unwrap's
        // its destinations (3-5).
        int first() {
            return wrap ? 0 : 3;
        }

        @Override
        protected void onMethodEnter() {
            pos = newLocal(Type.getType("[I"));
            loadArg(first());
            loadArg(first() + 1);
            loadArg(first() + 2);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, "positions", "([Ljava/nio/ByteBuffer;II)[I", false);
            storeLocal(pos);
            start = newLocal(Type.LONG_TYPE);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "nanoTime", "()J", false);
            storeLocal(start);
        }

        @Override
        protected void onMethodExit(int opcode) {
            if (opcode == ATHROW) {
                return;
            }
            dup(); // the result
            loadThis();
            swap();
            loadArg(first());
            loadArg(first() + 1);
            loadArg(first() + 2);
            loadLocal(pos);
            loadLocal(start);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, HOOKS, wrap ? "engineWrap" : "engineUnwrap",
                    "(Ljava/lang/Object;Ljavax/net/ssl/SSLEngineResult;[Ljava/nio/ByteBuffer;II[IJ)V", false);
        }
    }
}
