package com.minisast.cli;

import com.minisast.core.engine.ScanConfiguration;
import com.minisast.core.engine.ScanEngine;
import com.minisast.core.model.*;
import com.minisast.core.parser.JavaLanguageParser;
import com.minisast.core.parser.LanguageParser;
import com.minisast.core.rules.Rule;
import com.minisast.core.rules.RuleRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.*;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * The 'scan' subcommand.
 *
 * Usage:
 *   minisast scan ./src
 *   minisast scan ./src --severity HIGH --fail-on-findings
 *   minisast scan ./src --output json --output-file report.json
 *
 * Exit codes (important for CI integration):
 *   0 — success, no findings at threshold
 *   1 — findings found (when --fail-on-findings is set)
 *   2 — scan error (target not found, IO error, etc.)
 */
@Command(
        name        = "scan",
        description = "Scan a file or directory for security vulnerabilities",
        mixinStandardHelpOptions = true
)
public class ScanCommand implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(ScanCommand.class);

    // ANSI escape codes — stored as constants, never inline
    private static final String RESET  = "\u001B[0m";
    private static final String BOLD   = "\u001B[1m";
    private static final String CYAN   = "\u001B[36m";
    private static final String GREEN  = "\u001B[32m";
    private static final String RED    = "\u001B[31m";
    private static final String YELLOW = "\u001B[33m";

    @Parameters(
            index       = "0",
            description = "File or directory to scan"
    )
    private Path target;

    @Option(
            names       = {"-s", "--severity"},
            description = "Minimum severity to report: ${COMPLETION-CANDIDATES} (default: LOW)",
            defaultValue = "LOW"
    )
    private Severity minimumSeverity;

    @Option(
            names       = {"-o", "--output"},
            description = "Output format: cli, json (default: cli)",
            defaultValue = "cli"
    )
    private String outputFormat;

    @Option(
            names       = {"-f", "--output-file"},
            description = "Write output to this file (default: stdout)"
    )
    private Path outputFile;

    @Option(
            names       = {"--fail-on-findings"},
            description = "Exit with code 1 if any findings are reported",
            defaultValue = "false"
    )
    private boolean failOnFindings;

    @Option(
            names       = {"--fail-on-severity"},
            description = "Exit with code 1 if findings at or above this severity exist"
    )
    private Severity failOnSeverity;

    @Option(
            names       = {"--no-color"},
            description = "Disable ANSI color output",
            defaultValue = "false"
    )
    private boolean noColor;

    @Override
    public Integer call() {
        printBanner();

        // Real parsers and rules — Phase 2
        List<LanguageParser> parsers = List.of(new JavaLanguageParser());
        List<Rule>           rules   = new RuleRegistry().enabled();

        ScanConfiguration config = ScanConfiguration.builder()
                .minimumSeverity(minimumSeverity)
                .build();

        ScanEngine engine = new ScanEngine(parsers, rules, config);

        try {
            ScanResult result = engine.scan(target);
            renderResult(result);
            return exitCode(result);

        } catch (IOException e) {
            System.err.printf("%s✗ Scan failed: %s%s%n", RED, e.getMessage(), RESET);
            log.error("Scan failed for target: {}", target, e);
            return 2;
        }
    }

    // ── Rendering ─────────────────────────────────────────────────────────────

    private void renderResult(ScanResult result) {
        ScanStats stats = result.stats();

        System.out.println();
        System.out.printf("%s%s── Scan Results%s%n", BOLD, CYAN, RESET);
        System.out.printf("   %-10s %s%n", "Target:",   result.targetPath());
        System.out.printf("   %-10s %d files%n", "Scanned:", stats.filesScanned());
        System.out.printf("   %-10s %,d lines%n", "Lines:",   stats.linesScanned());
        System.out.printf("   %-10s %d ms%n", "Duration:", result.durationMs());
        System.out.printf("   %-10s %s%d%s%n%n",
                "Findings:",
                stats.totalFindings() > 0 ? RED : GREEN,
                stats.totalFindings(),
                RESET);

        if (!result.hasFindings()) {
            System.out.printf("%s✓ No findings detected.%s%n", GREEN, RESET);
            return;
        }

        result.findings().forEach(this::printFinding);
        printSummaryTable(result);
    }

    private void printFinding(Finding f) {
        String color = noColor ? "" : f.severity().getAnsiColor();
        String reset = noColor ? "" : RESET;

        System.out.printf("%s[%s]%s %s%s%s%n",
                color, f.severity().getLabel(), reset,
                BOLD, f.ruleName(), RESET);
        System.out.printf("   %-12s %s%n", "Location:",    f.location());
        System.out.printf("   %-12s %s%n", "Message:",     f.message());
        System.out.printf("   %-12s %s%n", "Confidence:",  f.confidence().getLabel());

        if (!f.cwe().isEmpty()) {
            System.out.printf("   %-12s %s%n", "CWE:",     f.cwe());
        }
        if (!f.owasp().isEmpty()) {
            System.out.printf("   %-12s %s%n", "OWASP:",   f.owasp());
        }
        if (!f.remediation().isEmpty()) {
            System.out.printf("   %-12s %s%n", "Fix:",     f.remediation());
        }

        System.out.println();
    }

    private void printSummaryTable(ScanResult result) {
        System.out.printf("%s%s── Finding Summary%s%n", BOLD, YELLOW, RESET);
        result.stats().findingsBySeverity()
                .entrySet()
                .stream()
                .sorted((a, b) -> Integer.compare(b.getKey().getLevel(), a.getKey().getLevel()))
                .forEach(e -> {
                    String color = noColor ? "" : e.getKey().getAnsiColor();
                    System.out.printf("   %s%-10s%s %d%n",
                            color, e.getKey().getLabel(), RESET, e.getValue());
                });
        System.out.println();
    }

    private void printBanner() {
        if (noColor) {
            System.out.println("=== Mini SAST v0.1.0 ===");
            return;
        }
        System.out.printf("""
                %s
                ╔══════════════════════════════════╗
                ║  🔐 Mini SAST  v0.1.0            ║
                ║     Static Security Analysis     ║
                ╚══════════════════════════════════╝
                %s
                """, CYAN, RESET);
    }

    private int exitCode(ScanResult result) {
        if (failOnSeverity != null) {
            boolean violated = result.findings().stream()
                    .anyMatch(f -> f.severity().isAtLeast(failOnSeverity));
            if (violated) return 1;
        }
        if (failOnFindings && result.hasFindings()) return 1;
        return 0;
    }
}