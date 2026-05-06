package com.minisast.core.report;

import com.minisast.core.model.*;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.Comparator;

/**
 * Produces human-readable terminal output with optional ANSI colours.
 *
 * Extracted from ScanCommand so CLI rendering is testable independently
 * and reusable (e.g. a future TUI or IDE plugin could use this reporter).
 *
 * Colour is disabled automatically when writing to a file (the caller
 * passes useColor=false). This prevents ANSI escape codes appearing in
 * saved reports which would make them unreadable in text editors.
 */
public final class CliReporter implements Reporter {

    private static final String RESET  = "\u001B[0m";
    private static final String BOLD   = "\u001B[1m";
    private static final String GREEN  = "\u001B[32m";
    private static final String RED    = "\u001B[31m";
    private static final String YELLOW = "\u001B[33m";
    private static final String CYAN   = "\u001B[36m";
    private static final String DIM    = "\u001B[2m";

    private final boolean useColor;

    public CliReporter(boolean useColor) {
        this.useColor = useColor;
    }

    /** Convenience constructor — colour enabled by default */
    public CliReporter() {
        this(true);
    }

    @Override
    public String getFormat() { return "cli"; }

    @Override
    public void report(ScanResult result, OutputStream output) throws IOException {
        // PrintWriter auto-flushes and handles encoding correctly
        PrintWriter out = new PrintWriter(output, true);

        printScanHeader(result, out);

        if (!result.hasFindings()) {
            out.printf("%s%s✓ No findings at or above the minimum severity threshold.%s%n",
                    bold(), green(), reset());
            return;
        }

        // Print findings sorted by severity descending
        result.findings().stream()
                .sorted(Comparator.comparingInt(f -> -f.severity().getLevel()))
                .forEach(f -> printFinding(f, out));

        printSummaryTable(result, out);
    }

    // ── Rendering ─────────────────────────────────────────────────────────────

    private void printScanHeader(ScanResult result, PrintWriter out) {
        ScanStats stats = result.stats();
        out.println();
        out.printf("%s%s── Scan Results%s%n", bold(), cyan(), reset());
        out.printf("   %-12s %s%n",  "Target:",   result.targetPath());
        out.printf("   %-12s %d%s%n", "Files:",    stats.filesScanned(),
                dim(" scanned"));
        out.printf("   %-12s %,d%s%n","Lines:",    stats.linesScanned(),
                dim(" analysed"));
        out.printf("   %-12s %d ms%n","Duration:", result.durationMs());
        out.printf("   %-12s %s%d%s%n%n", "Findings:",
                stats.totalFindings() > 0 ? red() : green(),
                stats.totalFindings(),
                reset());
    }

    private void printFinding(Finding f, PrintWriter out) {
        String severityColor = useColor ? f.severity().getAnsiColor() : "";

        out.printf("%s[%s]%s %s%s%s%n",
                severityColor, f.severity().getLabel(), reset(),
                bold(), f.ruleName(), reset());

        out.printf("   %-14s %s%n", "Location:",   f.location());
        out.printf("   %-14s %s%n", "Message:",    f.message());
        out.printf("   %-14s %s%n", "Confidence:", f.confidence().getLabel());

        if (!f.cwe().isBlank()) {
            out.printf("   %-14s %s%n", "CWE:",    f.cwe());
        }
        if (!f.owasp().isBlank()) {
            out.printf("   %-14s %s%n", "OWASP:",  f.owasp());
        }
        if (!f.remediation().isBlank()) {
            out.printf("   %-14s %s%n", "Fix:",    f.remediation());
        }
        if (!f.location().snippet().isBlank()) {
            out.printf("   %-14s %s%s%s%n", "Snippet:",
                    dim(), f.location().snippet(), reset());
        }
        out.println();
    }

    private void printSummaryTable(ScanResult result, PrintWriter out) {
        out.printf("%s%s── Summary%s%n", bold(), yellow(), reset());
        result.stats().findingsBySeverity()
                .entrySet()
                .stream()
                .sorted((a, b) -> Integer.compare(
                        b.getKey().getLevel(), a.getKey().getLevel()))
                .filter(e -> e.getValue() > 0)
                .forEach(e -> out.printf("   %s%-10s%s %d%n",
                        useColor ? e.getKey().getAnsiColor() : "",
                        e.getKey().getLabel(),
                        reset(),
                        e.getValue()));
        out.println();
    }

    // ── ANSI helpers — always returns empty string when color disabled ─────────

    private String reset()         { return useColor ? RESET  : ""; }
    private String bold()          { return useColor ? BOLD   : ""; }
    private String green()         { return useColor ? GREEN  : ""; }
    private String red()           { return useColor ? RED    : ""; }
    private String yellow()        { return useColor ? YELLOW : ""; }
    private String cyan()          { return useColor ? CYAN   : ""; }
    private String dim()           { return useColor ? DIM    : ""; }
    private String dim(String s)   { return useColor ? DIM + s + RESET : s; }
}