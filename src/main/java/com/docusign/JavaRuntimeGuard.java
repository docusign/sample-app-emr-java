package com.docusign;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Stops the app from starting on Java versions affected by CVE-2026-114938.
 *
 * Affected:
 *  - OpenJDK and derived distributions (Temurin, Corretto, Zulu, ...): 17.0.6 and later
 *  - Oracle Java SE: 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3
 */
public final class JavaRuntimeGuard {

    private static final Runtime.Version FIRST_AFFECTED_OPENJDK = Runtime.Version.parse("17.0.6");

    private static final List<String> AFFECTED_ORACLE_JAVA_SE =
            List.of("17.0.21.0.3", "21.0.13.0.3", "25.0.5.0.3", "27.0.1.0.3");

    private static final List<String> REQUIRED_CPU_FLAGS =
            List.of("avx512f", "avx512bw", "avx512vbmi", "bmi2");

    private JavaRuntimeGuard() {
    }

    public static void enforce() {
        Runtime.Version version = Runtime.version();
        boolean oracleJavaSe = System.getProperty("java.runtime.name", "").contains("Java(TM)");

        if (!isAffectedVersion(version, oracleJavaSe)) {
            return;
        }

        String message = "Java " + version + " is affected by CVE-2026-114938. Please install a fixed JDK.";

        if (!cpuHasRequiredFlags()) {
            System.err.println("WARNING: " + message + " This CPU is not vulnerable, so the app will start.");
            return;
        }
        if (Boolean.getBoolean("java.guard.allowAffected")) {
            System.err.println("WARNING: " + message + " Starting anyway because java.guard.allowAffected=true.");
            return;
        }
        System.err.println("ERROR: " + message);
        System.exit(1);
    }

    static boolean isAffectedVersion(Runtime.Version version, boolean oracleJavaSe) {
        if (oracleJavaSe) {
            String exact = version.version().stream().map(String::valueOf).collect(Collectors.joining("."));
            return AFFECTED_ORACLE_JAVA_SE.contains(exact);
        }
        return version.compareToIgnoreOptional(FIRST_AFFECTED_OPENJDK) >= 0;
    }

    static boolean cpuHasRequiredFlags() {
        String arch = System.getProperty("os.arch", "");
        if (arch.contains("aarch64") || arch.contains("arm")) {
            return false;
        }
        try {
            String flags;
            if (OSDetector.isLinux()) {
                flags = Files.readString(Paths.get("/proc/cpuinfo"));
            } else if (OSDetector.isMac()) {
                Process p = new ProcessBuilder("sysctl", "-n", "machdep.cpu.features", "machdep.cpu.leaf7_features").start();
                flags = new String(p.getInputStream().readAllBytes());
            } else {
                return true;
            }
            List<String> present = List.of(flags.toLowerCase().split("\\s+"));
            return present.containsAll(REQUIRED_CPU_FLAGS);
        } catch (Exception e) {
            return true;
        }
    }
}
