import snoopy.hooks.Hooks;

// The /dev/null transport's cost per frame, by payload size, in a loop on
// one thread, with the hooks jar on the boot class path:
//   java -Xbootclasspath/a:out/snoopy-hooks.jar -cp out/snoopy-hooks.jar spike/Bench.java
public class Bench {
    public static void main(String[] args) throws Exception {
        Hooks.enable(1, 16384);
        Object conn = new Object();
        for (int size : new int[] {64, 1024, 4096, 16384}) {
            byte[] b = new byte[size];
            int n = 200_000;
            for (int i = 0; i < n; i++) Hooks.socketWrite(conn, b, 0, size, System.nanoTime()); // warm up
            long[] lat = new long[n];
            long t0 = System.nanoTime();
            for (int i = 0; i < n; i++) {
                long s = System.nanoTime();
                Hooks.socketWrite(conn, b, 0, size, System.nanoTime());
                lat[i] = System.nanoTime() - s;
            }
            long total = System.nanoTime() - t0;
            java.util.Arrays.sort(lat);
            System.out.printf("%6d bytes: %6.0f ns/frame mean, p50 %d ns, p99 %d ns%n", size, (double) total / n, lat[n / 2], lat[n * 99 / 100]);
        }
    }
}
