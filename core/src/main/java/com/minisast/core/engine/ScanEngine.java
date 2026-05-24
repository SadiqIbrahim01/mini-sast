package com.minisast.core.engine;

import com.minisast.core.exception.ParseException;
import com.minisast.core.model.*;
import com.minisast.core.parser.ConfigFileParser;
import com.minisast.core.parser.JavaLanguageParser;
import com.minisast.core.parser.LanguageParser;
import com.minisast.core.rules.Rule;
import com.minisast.core.rules.RuleRegistry;
import com.minisast.core.rules.RuleMatch;
import com.minisast.core.walker.FileWalker;
import com.minisast.core.walker.IgnorePatterns;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Orchestrates a complete scan.
 *
 * Responsibilities:
 *   1. Walk the file tree (via FileWalker)
 *   2. Dispatch each file to the correct LanguageParser
 *   3. Run applicable rules per file
 *   4. Convert RuleMatches -> Findings
 *   5. Return a complete, immutable ScanResult
 *
 * This class is intentionally free of Spring, CLI, or API concerns.
 * It can be instantiated and called from any context.
 *
 * Thread safety: ScanEngine is stateless after construction.
 * The same instance can run concurrent scans safely (Phase 6).
 *
 * Use createDefault() or defaultParsers() as the single source of truth
 * for parser registration. Never construct parser lists manually in
 * consumers — that causes environment drift between production and tests.
 */
public final class ScanEngine {

    private static final Logger log = LoggerFactory.getLogger(ScanEngine.class);
    public  static final String ENGINE_VERSION = "0.1.0";

    private final List<LanguageParser> parsers;
    private final List<Rule>           rules;
    private final ScanConfiguration    config;
    private final SuppressionFilter suppressionFilter = new SuppressionFilter();

    public ScanEngine(
            List<LanguageParser> parsers,
            List<Rule>           rules,
            ScanConfiguration    config
    ) {
        this.parsers = List.copyOf(parsers);
        this.rules   = List.copyOf(rules);
        this.config  = config;
    }

    // ── Factory methods ───────────────────────────────────────────────────────

    /**
     * Returns the canonical list of all built-in language parsers.
     *
     * This is the single source of truth for parser registration.
     * Adding a new parser here automatically affects CLI, API, and tests.
     * Never construct this list manually in consumers.
     */
    public static List<LanguageParser> defaultParsers() {
        return List.of(
                new JavaLanguageParser(),
                new ConfigFileParser()
        );
    }

    /**
     * Creates a fully configured engine with default parsers, all enabled
     * rules, and default scan configuration.
     *
     * Use in integration tests and anywhere a standard scan is needed
     * without custom configuration overrides.
     */
    public static ScanEngine createDefault() {
        return new ScanEngine(
                defaultParsers(),
                new RuleRegistry().enabled(),
                ScanConfiguration.defaults()
        );
    }

    // ── Core scan ─────────────────────────────────────────────────────────────

    /**
     * Execute a scan against a file or directory.
     *
     * @param  target  Path to scan (file or directory)
     * @return         Immutable ScanResult
     * @throws IOException if the target cannot be accessed
     */
    public ScanResult scan(Path target) throws IOException {
        log.info("Scan started | target={} | rules={} | parsers={}",
                target.toAbsolutePath(), rules.size(), parsers.size());

        long startMs = System.currentTimeMillis();

        // Load ignore patterns from the target directory
        Path ignoreRoot = Files.isDirectory(target) ? target : target.getParent();
        IgnorePatterns ignorePatterns = IgnorePatterns.loadFrom(ignoreRoot);

        // Discover all files
        FileWalker walker = new FileWalker(ignorePatterns);
        List<Path> files  = walker.walk(target);

        // Analyse each file
        List<Finding> findings    = new ArrayList<>();
        int           filesScanned = 0;
        long          totalLines   = 0L;

        for (Path file : files) {
            Optional<LanguageParser> parser = findParser(file);

            if (parser.isEmpty()) {
                log.debug("No parser available for: {}", file);
                continue;
            }

            filesScanned++;
            totalLines += countLines(file);

            List<Rule> applicable = applicableRules(parser.get().getLanguage());
            log.debug("Analysing {} with {} rules", file.getFileName(), applicable.size());

            try {
                List<RuleMatch> rawMatches = parser.get().analyze(file, applicable);

                // Apply inline suppression comments before converting to findings
                List<RuleMatch> matches = suppressionFilter.filter(file, rawMatches);

                matches.stream()
                        .filter(m -> ruleFor(m.ruleId())
                                .map(r -> r.getSeverity().isAtLeast(config.minimumSeverity()))
                                .orElse(false))
                        .map(m -> toFinding(m, ruleFor(m.ruleId()).orElseThrow()))
                        .forEach(findings::add);

            } catch (ParseException e) {
                log.warn("Parse error in {} — {}", file, e.getMessage());
                if (config.failOnParseError()) {
                    throw new IOException(
                            "Scan aborted due to parse error: " + e.getMessage(), e);
                }
            }
        }

        long durationMs = System.currentTimeMillis() - startMs;

        ScanResult result = ScanResult.of(
                target.toAbsolutePath().toString(),
                durationMs,
                ENGINE_VERSION,
                findings,
                filesScanned,
                totalLines
        );

        log.info("Scan complete | files={} | findings={} | duration={}ms",
                filesScanned, findings.size(), durationMs);

        return result;
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private Optional<LanguageParser> findParser(Path file) {
        return parsers.stream().filter(p -> p.supports(file)).findFirst();
    }

    private List<Rule> applicableRules(Language language) {
        String lang = language.name().toLowerCase();
        return rules.stream()
                .filter(Rule::isEnabled)
                .filter(r -> !config.isRuleDisabled(r.getId())) // ← honour disabled rules
                .filter(r -> r.getLanguage().equals("*")
                        || r.getLanguage().equalsIgnoreCase(lang))
                .toList();
    }

    private Optional<Rule> ruleFor(String ruleId) {
        return rules.stream().filter(r -> r.getId().equals(ruleId)).findFirst();
    }

    private Finding toFinding(RuleMatch match, Rule rule) {
        return Finding.builder()
                .ruleId(rule.getId())
                .ruleName(rule.getName())
                .description(rule.getDescription())
                .severity(rule.getSeverity())
                .confidence(match.confidence())
                .location(match.location())
                .message(match.message())
                .remediation(rule.getRemediation())
                .cwe(rule.getCwe())
                .owasp(rule.getOwasp())
                .build();
    }

    private long countLines(Path file) {
        try (var lines = Files.lines(file)) {
            return lines.count();
        } catch (IOException e) {
            log.debug("Could not count lines for: {}", file);
            return 0L;
        }
    }
}