package com.minisast.cli;

import com.minisast.core.config.ConfigLoader;
import com.minisast.core.config.MiniSastConfig;
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
import java.util.HashSet;
import java.util.Set;
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

    @Option(
            names       = {"-c", "--config"},
            description = "Path to .minisast.yml config file " +
                    "(default: auto-discovered from scan target directory)"
    )
    private Path configFile;

    @Override
    public Integer call() {
        printBanner();

        // ── Load config (file takes precedence, then auto-discovery) ─────────────
        MiniSastConfig projectConfig = loadConfig();

        // ── Merge: CLI flags override config file values ──────────────────────────
        Severity    effectiveSeverity  = resolveMinimumSeverity(projectConfig);
        boolean     effectiveFailOnFindings = failOnFindings || projectConfig.getScan().isFailOnFindings();
        Severity    effectiveFailOnSev = resolveFailOnSeverity(projectConfig);
        Set<String> disabledRules      = new HashSet<>(projectConfig.getRules().getDisable());
        String      effectiveFormat    = outputFormat.equals("cli")
                && !projectConfig.getOutput().getFormat().equals("cli")
                ? projectConfig.getOutput().getFormat()
                : outputFormat;
        Path        effectiveOutputFile = outputFile != null
                ? outputFile
                : resolveOutputFile(projectConfig);

        ScanConfiguration config = ScanConfiguration.builder()
                .minimumSeverity(effectiveSeverity)
                .disabledRules(disabledRules)
                .build();

        ScanEngine engine = new ScanEngine(
                ScanEngine.defaultParsers(),
                new RuleRegistry().enabled(),
                config
        );

        try {
            ScanResult result = engine.scan(target);
            writeReport(result, effectiveFormat, effectiveOutputFile);
            return exitCode(result, effectiveFailOnFindings, effectiveFailOnSev);

        } catch (IOException e) {
            System.err.printf("%s✗ Scan failed: %s%s%n",
                    noColor ? "" : "\u001B[31m", e.getMessage(),
                    noColor ? "" : "\u001B[0m");
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

    // ── Config loading and merging ─────────────────────────────────────────────

    private MiniSastConfig loadConfig() {
        if (configFile != null) {
            try {
                return ConfigLoader.load(configFile);
            } catch (IOException e) {
                System.err.printf("⚠ Failed to load config file %s: %s%n",
                        configFile, e.getMessage());
                return new MiniSastConfig();
            }
        }
        return ConfigLoader.discover(target).orElse(new MiniSastConfig());
    }

    private Severity resolveMinimumSeverity(MiniSastConfig config) {
        // CLI flag default is LOW — if user didn't change it, use config file value
        if (minimumSeverity == Severity.LOW) {
            try {
                return Severity.valueOf(
                        config.getScan().getMinimumSeverity().toUpperCase());
            } catch (IllegalArgumentException e) {
                log.warn("Invalid minimumSeverity in config: {}",
                        config.getScan().getMinimumSeverity());
            }
        }
        return minimumSeverity;
    }

    private Severity resolveFailOnSeverity(MiniSastConfig config) {
        if (failOnSeverity != null) return failOnSeverity;
        String cfgSev = config.getScan().getFailOnSeverity();
        if (cfgSev != null && !cfgSev.isBlank()) {
            try {
                return Severity.valueOf(cfgSev.toUpperCase());
            } catch (IllegalArgumentException e) {
                log.warn("Invalid failOnSeverity in config: {}", cfgSev);
            }
        }
        return null;
    }

    private Path resolveOutputFile(MiniSastConfig config) {
        String cfgFile = config.getOutput().getFile();
        if (cfgFile != null && !cfgFile.isBlank()) {
            return Path.of(cfgFile);
        }
        return null;
    }

    private void writeReport(ScanResult result, String format, Path outFile) throws IOException {
        boolean colorize = !noColor && outFile == null;
        Reporter reporter = ReporterFactory.forFormat(format, colorize);

        if (outFile != null) {
            try (OutputStream out = new FileOutputStream(outFile.toFile())) {
                reporter.report(result, out);
            }
            System.out.printf("Report written to: %s%n", outFile.toAbsolutePath());
        } else {
            reporter.report(result, System.out);
            System.out.flush();
        }
    }

    private int exitCode(ScanResult result, boolean failOnAny, Severity failSeverity) {
        if (failSeverity != null) {
            boolean violated = result.findings().stream()
                    .anyMatch(f -> f.severity().isAtLeast(failSeverity));
            if (violated) return 1;
        }
        if (failOnAny && result.hasFindings()) return 1;
        return 0;
    }
}