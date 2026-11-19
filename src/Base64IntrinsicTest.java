import com.sun.management.HotSpotDiagnosticMXBean;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.nio.charset.Charset;
import java.util.Locale;

/**
 * Base64IntrinsicTest - dynamic probe for CVE-2026-114938 ("Java4Shell").
 *
 * Unlike a static version/CPU scanner, this program determines the result
 * EMPIRICALLY, from WITHIN the JVM under test:
 *
 *   1. It reads its own runtime version and decides whether that build is in the
 *      vulnerable range (OpenJDK-based 17.0.6+, and all of 21/25/27 below the fix).
 *   2. It reads, in-process, the VM options the JVM actually negotiated for THIS
 *      CPU - UseAVX and UseBASE64Intrinsics - via HotSpotDiagnosticMXBean. The
 *      vulnerable hand-written AVX-512 VBMI Base64 decode stub is only installed
 *      and used when UseBASE64Intrinsics is on AND the CPU exposes AVX-512
 *      (UseAVX>=3); on Linux it additionally confirms the avx512vbmi CPU flag.
 *   3. It exercises java.util.Base64 decoding in a warm-up loop so the C2 JIT
 *      actually compiles the vectorized intrinsic. If the machine is genuinely
 *      affected this is the code path an attacker reaches; completing it cleanly
 *      and still printing a verdict is itself part of the signal (a hard JVM
 *      crash means no verdict line is printed - the launcher treats that as a
 *      strong AFFECTED indication).
 *
 * The ONLY authoritative output is the single line beginning:
 *      JAVA4SHELL_RESULT:
 * Everything the caller needs to decide is derived from that line (and the
 * process exit code). Run this file; read its output; that is the result.
 *
 * Source level: Java 8 (runs under any Java 8+ runtime under test).
 */
public final class Base64IntrinsicTest {

    static final String CVE = "CVE-2026-114938";
    static volatile int sink;

    public static void main(String[] args) {
        boolean quiet = false;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--quiet")) quiet = true;
            else if (args[i].equals("--help") || args[i].equals("-h")) { help(); return; }
        }

        String version = System.getProperty("java.version", "");
        String vendor = System.getProperty("java.vendor", "");
        String runtime = System.getProperty("java.runtime.version", version);
        String arch = System.getProperty("os.arch", "");

        // ---- (1) version decision --------------------------------------------
        boolean vulnVersion = isVulnerableVersion(version);

        // ---- (2) in-process VM-option / CPU decision -------------------------
        int useAvx = readIntOption("UseAVX", -1);
        boolean base64Intrinsics = readBoolOption("UseBASE64Intrinsics", true);
        boolean isArm = arch.toLowerCase(Locale.ROOT).contains("arm")
                || arch.toLowerCase(Locale.ROOT).contains("aarch64");
        boolean avx512 = !isArm && useAvx >= 3;            // AVX-512 negotiated by the VM
        Boolean vbmiConfirmed = linuxHasVbmi();            // precise on Linux, else null

        // ---- (3) actually drive the vectorized intrinsic ---------------------
        boolean exercised = exerciseBase64Intrinsic();

        // ---- combine: POINT-IN-TIME verdict ---------------------------------
        // Question answered: is the vulnerable code path reachable on THIS JVM, on
        // THIS hardware, AS CONFIGURED, right now? The JVM stays on this hardware,
        // so "what if it were moved to an AVX-512 host" is deliberately out of scope.
        //
        // The vulnerable path can actually execute now only if ALL of these hold:
        //   - the build is in the affected version range, AND
        //   - UseBASE64Intrinsics is enabled (the vulnerable stub can run), AND
        //   - the CPU actually runs AVX-512 (UseAVX>=3; avx512vbmi where confirmable).
        // If any is false, the bug cannot be triggered on this host as it stands.
        boolean cpuAvx512 = avx512 && (vbmiConfirmed == null || vbmiConfirmed.booleanValue());
        boolean vulnerableNow = vulnVersion && !isArm && base64Intrinsics && cpuAvx512;

        String verdict = vulnerableNow ? "VULNERABLE" : "NOT_VULNERABLE";
        String model = cpuModel();
        String modelTag = model.isEmpty() ? "" : " [" + model + "]";

        String reason;
        if (vulnerableNow) {
            reason = "affected build, Base64 intrinsic enabled, and AVX-512 active on this CPU"
                    + (vbmiConfirmed == null ? " (UseAVX=3; confirm AVX-512 VBMI / Ice Lake+/Zen 4+)"
                                             : " (avx512vbmi confirmed)");
        } else if (!vulnVersion) {
            reason = "runtime " + version + " is not an affected build";
        } else if (isArm) {
            reason = "ARM architecture - the AVX-512 Base64 intrinsic does not exist here";
        } else if (!base64Intrinsics) {
            reason = "affected build, but UseBASE64Intrinsics is disabled - the vulnerable path cannot execute"
                    + (cpuAvx512 ? "" : " (this CPU also has no AVX-512, UseAVX=" + useAvx + ")" + modelTag);
        } else { // intrinsics enabled but the CPU has no AVX-512
            reason = "affected build with intrinsics enabled, but this CPU has no AVX-512 (UseAVX=" + useAvx
                    + ")" + modelTag + " - the vulnerable path is not used";
        }

        if (!quiet) {
            System.out.println("Java4Shell dynamic probe (" + CVE + ")  [point-in-time check]");
            System.out.println("  runtime            : " + runtime + "  [" + vendor + "]");
            System.out.println("  os.arch            : " + arch + (model.isEmpty() ? "" : "   " + model));
            System.out.println("  affected build     : " + vulnVersion + "   (version is in the vulnerable range)");
            System.out.println("  UseBASE64Intrinsics: " + base64Intrinsics
                    + "   (vulnerable intrinsic " + (base64Intrinsics ? "ENABLED" : "disabled") + ")");
            System.out.println("  UseAVX             : " + (useAvx < 0 ? "unknown" : String.valueOf(useAvx))
                    + (cpuAvx512 ? "  (AVX-512 active)" : "  (no AVX-512)"));
            System.out.println("  avx512vbmi (Linux) : " + (vbmiConfirmed == null ? "not determinable here" : vbmiConfirmed));
            System.out.println("  intrinsic exercised: " + exercised + "  (last decoded length=" + sink + ")");
            System.out.println("  VULNERABLE NOW     : " + vulnerableNow);
            System.out.println("  reason             : " + reason);
        }

        // The authoritative, machine-readable result line.
        System.out.println("JAVA4SHELL_RESULT: " + verdict + " | vulnerableNow=" + vulnerableNow
                + " | version=" + version + " | affectedBuild=" + vulnVersion
                + " | useAVX=" + useAvx + " | base64Intrinsics=" + base64Intrinsics
                + " | reason=" + reason);

        System.exit(vulnerableNow ? 2 : 0);
    }

    /** Force C2 to compile and run the vectorized Base64 decode intrinsic. */
    static boolean exerciseBase64Intrinsic() {
        try {
            byte[] raw = new byte[128];
            for (int i = 0; i < raw.length; i++) raw[i] = 'A';
            byte[] encoded = java.util.Base64.getEncoder().encode(raw);
            byte[] out = new byte[256];
            java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();
            for (int i = 0; i < 20000; i++) {
                int written = decoder.decode(encoded, out);
                sink = written; // defeat dead-code elimination
            }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    // --------------------------------------------------- in-process VM flags ----

    static int readIntOption(String name, int dflt) {
        try {
            HotSpotDiagnosticMXBean b = ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class);
            String v = b.getVMOption(name).getValue();
            return Integer.parseInt(v.trim());
        } catch (Throwable t) {
            return dflt;
        }
    }

    static boolean readBoolOption(String name, boolean dflt) {
        try {
            HotSpotDiagnosticMXBean b = ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class);
            return Boolean.parseBoolean(b.getVMOption(name).getValue().trim());
        } catch (Throwable t) {
            return dflt;
        }
    }

    /** True/false from /proc/cpuinfo on Linux; null when not determinable. */
    static Boolean linuxHasVbmi() {
        File f = new File("/proc/cpuinfo");
        if (!f.canRead()) return null;
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(f));
            String line;
            while ((line = r.readLine()) != null) {
                String low = line.toLowerCase(Locale.ROOT);
                if (low.startsWith("flags") || low.startsWith("features")) {
                    return Boolean.valueOf(low.contains("avx512vbmi"));
                }
            }
            return Boolean.FALSE;
        } catch (IOException e) {
            return null;
        } finally {
            if (r != null) try { r.close(); } catch (IOException ignore) {}
        }
    }

    /** Best-effort CPU model string for secondary confirmation. */
    static String cpuModel() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("linux")) {
            BufferedReader r = null;
            try {
                r = new BufferedReader(new FileReader("/proc/cpuinfo"));
                String line;
                while ((line = r.readLine()) != null) {
                    if (line.toLowerCase(Locale.ROOT).startsWith("model name")) {
                        int i = line.indexOf(':');
                        return i >= 0 ? line.substring(i + 1).trim() : line.trim();
                    }
                }
            } catch (IOException ignore) {
            } finally { if (r != null) try { r.close(); } catch (IOException ignore) {} }
        }
        // On Windows PROCESSOR_IDENTIFIER is always present; on macOS Intel this is empty
        // (ARM macs are already ruled out as not-affected before we reach here).
        String id = System.getenv("PROCESSOR_IDENTIFIER");
        return id == null ? "" : id;
    }

    // ----------------------------------------------------- version decision ----

    static boolean isVulnerableVersion(String raw) {
        int[] v = parse(raw);
        if (v.length == 0) return false;
        int feature = v[0];

        if (feature == 8) {
            if (raw.toLowerCase(Locale.ROOT).contains("perf")) {
                int u = legacyUpdate(raw);
                return u < 0 || u < 513;            // Oracle 8 EPP: fixed 8u513-perf
            }
            return false;
        }
        if (feature < 17) return false;             // 8 / 11 not affected

        int[][] fixes = {
            {17, 17, 0, 21, 1}, {21, 21, 0, 13, 1}, {25, 25, 0, 5, 1}, {27, 27, 0, 1, 1}
        };
        for (int[] f : fixes) {
            if (feature == f[0]) {
                int[] fix = {f[1], f[2], f[3], f[4]};
                if (feature == 17 && cmp(v, new int[]{17, 0, 6}) < 0) return false; // 17.0.6 lower bound
                return cmp(v, fix) < 0;
            }
        }
        // Interim non-LTS lines (18-20, 22-24, 26) in the affected era.
        if (feature <= 27) return true;
        return false;                               // newer than all known fixes
    }

    static int[] parse(String s) {
        if (s == null) return new int[0];
        String v = s.trim();
        if (v.startsWith("1.")) {
            String[] parts = v.split("[._+\\-]");
            java.util.List<Integer> n = new java.util.ArrayList<Integer>();
            for (String p : parts) { if (p.matches("\\d+")) n.add(Integer.valueOf(Integer.parseInt(p))); else break; }
            if (n.size() >= 2) { int[] o = new int[n.size() - 1]; for (int i = 1; i < n.size(); i++) o[i - 1] = n.get(i).intValue(); return o; }
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < v.length(); i++) { char c = v.charAt(i); if (Character.isDigit(c) || c == '.') sb.append(c); else break; }
        String[] parts = sb.toString().split("\\.");
        java.util.List<Integer> n = new java.util.ArrayList<Integer>();
        for (String p : parts) { if (p.isEmpty()) continue; try { n.add(Integer.valueOf(Integer.parseInt(p))); } catch (NumberFormatException e) { break; } }
        int[] o = new int[n.size()]; for (int i = 0; i < o.length; i++) o[i] = n.get(i).intValue(); return o;
    }

    static int legacyUpdate(String raw) {
        int u = raw.indexOf('_'); if (u < 0) return -1;
        StringBuilder sb = new StringBuilder();
        for (int i = u + 1; i < raw.length(); i++) { char c = raw.charAt(i); if (Character.isDigit(c)) sb.append(c); else break; }
        try { return sb.length() > 0 ? Integer.parseInt(sb.toString()) : -1; } catch (NumberFormatException e) { return -1; }
    }

    static int cmp(int[] a, int[] b) {
        int n = Math.max(a.length, b.length);
        for (int i = 0; i < n; i++) { int x = i < a.length ? a[i] : 0, y = i < b.length ? b[i] : 0; if (x != y) return x < y ? -1 : 1; }
        return 0;
    }

    static void help() {
        System.out.println("Base64IntrinsicTest - dynamic probe for " + CVE + " (Java4Shell)");
        System.out.println();
        System.out.println("Run this class/JAR UNDER the JVM you want to test. It inspects that JVM's");
        System.out.println("negotiated VM options and version in-process and answers a POINT-IN-TIME");
        System.out.println("question: is the vulnerable Base64 path reachable on this JVM, on this");
        System.out.println("hardware, as configured, right now? It prints a single result line:");
        System.out.println();
        System.out.println("  JAVA4SHELL_RESULT: <VULNERABLE|NOT_VULNERABLE> | vulnerableNow=... | ...");
        System.out.println();
        System.out.println("VULNERABLE requires ALL of: affected build AND UseBASE64Intrinsics=true AND");
        System.out.println("AVX-512 active (UseAVX>=3). If any is false the bug cannot execute here.");
        System.out.println("Exit codes: 2=vulnerable now, 0=not vulnerable now.");
        System.out.println("Options: --quiet (only the result line), --help.");
    }

    @SuppressWarnings("unused")
    private static Charset unusedKeepImport = Charset.defaultCharset();

    private Base64IntrinsicTest() {}
}
