package com.minisast.cli;

import com.minisast.core.engine.ScanConfiguration;
import com.minisast.core.engine.ScanEngine;
import com.minisast.core.model.ScanResult;
import com.minisast.core.model.Severity;
import com.minisast.core.report.Reporter;
import com.minisast.core.report.ReporterFactory;
import com.minisast.core.rules.RuleRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.*;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(
        name        = "scan",
        description = "Scan a file or directory for security vulnerabilities",
        mixinStandardHelpOptions = true
)
public class ScanCommand implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(ScanCommand.class);

    private static final String CYAN  = "\u001B[36m";
    private static final String RESET = "\u001B[0m";

    @Parameters(
            index       = "0",
            description = "File or directory to scan"
    )
    private Path target;

    @Option(
            names       = {"-s", "--severity"},
            description = "Minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW, INFO (default: LOW)",
            defaultValue = "LOW"
    )
    private Severity minimumSeverity;

    @Option(
            names       = {"-o", "--output"},
            description = "Output format: " + "cli, json, html (default: cli)",
            defaultValue = "cli"
    )
    private String outputFormat;

    @Option(
            names       = {"-f", "--output-file"},
            description = "Write report to this file (default: stdout)"
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

        ScanConfiguration config = ScanConfiguration.builder()
                .minimumSeverity(minimumSeverity)
                .build();

        ScanEngine engine = new ScanEngine(
                ScanEngine.defaultParsers(),
                new RuleRegistry().enabled(),
                config
        );

        try {
            ScanResult result = engine.scan(target);
            writeReport(result);
            return exitCode(result);

        } catch (IOException e) {
            System.err.printf("%s✗ Scan failed: %s%s%n",
                    noColor ? "" : "\u001B[31m", e.getMessage(),
                    noColor ? "" : RESET);
            log.error("Scan failed for target: {}", target, e);
            return 2;
        }
    }

    // ── Report output ─────────────────────────────────────────────────────────

    private void writeReport(ScanResult result) throws IOException {
        // Disable color when writing to a file — ANSI codes are noise in saved files
        boolean colorize = !noColor && outputFile == null;
        Reporter reporter = ReporterFactory.forFormat(outputFormat, colorize);

        if (outputFile != null) {
            try (OutputStream out = new FileOutputStream(outputFile.toFile())) {
                reporter.report(result, out);
            }
            System.out.printf("Report written to: %s%n",
                    outputFile.toAbsolutePath());
        } else {
            reporter.report(result, System.out);
            System.out.flush();
        }
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

    private void printBanner() {
        if (noColor) {
            System.out.println("=== Mini SAST v0.1.0 ===\n");
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
}