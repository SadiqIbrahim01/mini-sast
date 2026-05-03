package com.minisast.core.rules.config;

import com.minisast.core.model.Confidence;
import com.minisast.core.model.Location;
import com.minisast.core.model.Severity;
import com.minisast.core.rules.AbstractRule;
import com.minisast.core.rules.RuleMatch;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Detects hardcoded secrets in configuration files.
 *
 * Handles: .env, .properties, .yml, .yaml, .toml, .ini, .conf
 *
 * KEY DESIGN DECISIONS:
 *
 * 1. File-name-based suppression
 *    Files named *.example, *.template, *.sample, *.dist are documentation.
 *    They are excluded before any line is analysed.
 *    Developers use these to document what variables exist without exposing values.
 *
 * 2. Reference detection (most important false-positive prevention)
 *    A KEY=VALUE pair where VALUE is itself a reference is safe:
 *      DB_PASSWORD=${DB_PASSWORD}      → references an env var → skip
 *      DB_PASSWORD=#{env['DB_PASS']}   → Spring EL reference → skip
 *      DB_PASSWORD=                    → empty → skip
 *      DB_PASSWORD=<your-password>     → placeholder → skip
 *    A KEY=VALUE pair where VALUE is a real string is suspicious:
 *      DB_PASSWORD=Xk9#mP2$vL8@nR4q   → real value → flag
 *
 * 3. Key-name sensitivity
 *    Same sensitive name fragments as HardcodedSecretRule.
 *    Config files use UPPER_SNAKE_CASE keys — we normalise before matching.
 *
 * 4. Shannon entropy applied to the VALUE portion only
 *    Same 3.5 HIGH / 3.3 MEDIUM thresholds as HardcodedSecretRule.
 *    Applied AFTER reference and placeholder checks.
 *
 * 5. YAML/TOML inline values
 *    Handles both KEY=VALUE (.env, .properties) and KEY: VALUE (.yml) formats.
 *
 * CWE-798: Use of Hard-coded Credentials
 * OWASP A07:2021 - Identification and Authentication Failures
 */
public final class ConfigSecretRule extends AbstractRule {

    // ── Sensitive key name fragments ─────────────────────────────────────────
    // Config files use UPPER_SNAKE_CASE — normalise to lowercase before check
    private static final Set<String> SENSITIVE_KEY_FRAGMENTS = Set.of(
            "password", "passwd", "pwd",
            "secret",   "secretkey",
            "apikey",   "apitoken", "api_key", "api_token",
            "token",    "accesstoken", "access_token",
            "privatekey", "private_key",
            "credential", "credentials",
            "authtoken", "auth_token",
            "clientsecret", "client_secret",
            "dbpassword", "db_password", "dbpass",
            "connectionstring", "connection_string",
            "encryptionkey", "encryption_key",
            "signingkey", "signing_key",
            "masterkey", "master_key"
    );

    // ── Known secret format patterns ─────────────────────────────────────────
    private static final List<Pattern> SECRET_PATTERNS = List.of(
            Pattern.compile("AKIA[0-9A-Z]{16}"),
            Pattern.compile("ghp_[a-zA-Z0-9]{36}"),
            Pattern.compile("ghs_[a-zA-Z0-9]{36}"),
            Pattern.compile("sk-[a-zA-Z0-9]{20,}"),
            Pattern.compile("xox[bpoa]-[a-zA-Z0-9-]{10,}"),
            Pattern.compile("eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+"),
            Pattern.compile("-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----")
    );

    // ── Reference patterns — values that point elsewhere, not hardcoded ──────
    // These patterns mean the value is a REFERENCE, not a hardcoded credential.
    // Safe to skip regardless of key name or entropy.
    private static final List<Pattern> REFERENCE_PATTERNS = List.of(
            Pattern.compile("^\\$\\{[^}]+\\}$"),        // ${ENV_VAR}
            Pattern.compile("^\\$[A-Z_][A-Z0-9_]*$"),   // $ENV_VAR (shell style)
            Pattern.compile("^#\\{[^}]+\\}$"),           // #{Spring EL expression}
            Pattern.compile("^%\\([^)]+\\)s$"),           // %(python_style)s
            Pattern.compile("^@[A-Za-z.]+@$"),           // @maven.property@
            Pattern.compile("^\\{\\{[^}]+\\}\\}$"),      // {{handlebars_template}}
            Pattern.compile("^vault:[a-zA-Z0-9/]+$"),    // vault:secret/path
            Pattern.compile("^arn:aws:[a-zA-Z0-9:/-]+$") // AWS ARN reference
    );

    // ── Placeholder value patterns ────────────────────────────────────────────
    private static final List<Pattern> PLACEHOLDER_PATTERNS = List.of(
            Pattern.compile("^\\{[^}]+\\}$"),            // {YOUR_VALUE}
            Pattern.compile("^<[^>]+>$"),                // <your-value>
            Pattern.compile("^\\[[^]]+\\]$")             // [your-value]
    );

    // ── Filename suffixes that indicate documentation files ──────────────────
    // These files are committed intentionally and document what variables exist.
    // They must NEVER be flagged regardless of their content.
    private static final Set<String> DOCUMENTATION_SUFFIXES = Set.of(
            ".example", ".template", ".sample",
            ".dist",    ".tpl",      ".default",
            ".placeholder"
    );

    // ── Instruction verbs that indicate placeholder intent ───────────────────
    private static final Set<String> PLACEHOLDER_VERBS = Set.of(
            "insert", "replace", "add", "put", "fill", "enter",
            "your", "here", "todo", "changeme", "placeholder",
            "example", "sample", "test", "dummy", "fake", "mock",
            "configure", "set", "define", "update", "override"
    );

    private static final double HIGH_ENTROPY_THRESHOLD   = 3.5;
    private static final double MEDIUM_ENTROPY_THRESHOLD = 3.3;
    private static final int    MIN_VALUE_LENGTH         = 8;

    public ConfigSecretRule() {
        super(
                "CONFIG-SEC-001",
                "Hardcoded Secret in Config File",
                "A credential or secret value is hardcoded directly in a configuration file. " +
                        "Configuration files committed to version control expose secrets permanently.",
                Severity.CRITICAL,  // Higher than Java code — config files are committed more often
                Confidence.HIGH,
                "*",                // applies to all languages — ConfigFileParser filters to config only
                "CWE-798",
                "A07:2021 - Identification and Authentication Failures",
                "Use environment variable references: DB_PASSWORD=${DB_PASSWORD}. " +
                        "Store actual values in a secrets manager (AWS Secrets Manager, HashiCorp Vault) " +
                        "or inject them at runtime via your deployment platform. " +
                        "Add .env to .gitignore immediately."
        );
    }

    /**
     * Analyses a single line from a config file.
     * Called by ConfigFileParser for each line — not AST-based.
     *
     * @param line      Raw line content
     * @param lineNum   1-based line number
     * @param filePath  Absolute path to the config file
     * @param fileName  Just the filename (for documentation suffix check)
     * @return          Optional RuleMatch, empty if line is safe
     */
    public Optional<RuleMatch> analyzeLine(
            String line,
            int    lineNum,
            String filePath,
            String fileName
    ) {
        // Gate 1: Documentation file — never flag regardless of content
        if (isDocumentationFile(fileName)) return Optional.empty();

        // Gate 2: Skip blank lines and comments
        String trimmed = line.trim();
        if (trimmed.isEmpty() || isComment(trimmed)) return Optional.empty();

        // Gate 3: Parse the key=value pair
        KeyValue kv = parseLine(trimmed);
        if (kv == null) return Optional.empty(); // not a key=value line

        // Gate 4: Skip if value is empty
        if (kv.value().isBlank()) return Optional.empty();

        // Gate 5: Skip if value is a reference (${ENV_VAR}, $VAR, etc.)
        if (isReference(kv.value())) return Optional.empty();

        // Gate 6: Skip placeholders and instruction text
        if (isPlaceholder(kv.value())) return Optional.empty();
        if (containsPlaceholderVerb(kv.value())) return Optional.empty();

        // Gate 7: Skip values too short to be real secrets
        if (kv.value().length() < MIN_VALUE_LENGTH) return Optional.empty();

        // Now evaluate signals
        boolean sensitiveKey    = isSensitiveKey(kv.key());
        boolean knownPattern    = matchesKnownPattern(kv.value());
        double  entropy         = shannonEntropy(kv.value());
        boolean highEntropy     = entropy >= HIGH_ENTROPY_THRESHOLD;
        boolean mediumEntropy   = entropy >= MEDIUM_ENTROPY_THRESHOLD;

        Confidence confidence = determineConfidence(
                sensitiveKey, knownPattern, highEntropy, mediumEntropy
        );

        if (confidence == null) return Optional.empty();

        String reason = buildReason(kv.key(), sensitiveKey, knownPattern, entropy);

        Location location = new Location(
                filePath, lineNum, lineNum, 0, 0,
                kv.key() + "=" + redact(kv.value())
        );

        return Optional.of(new RuleMatch(
                getId(),
                location,
                reason + "This file should not be committed with real credential values.",
                confidence
        ));
    }

    // ── Parsing ───────────────────────────────────────────────────────────────

    /**
     * Parses a line into a key-value pair.
     * Handles three formats:
     *   KEY=VALUE          (.env, .properties)
     *   KEY: VALUE         (.yml, .yaml)
     *   KEY = VALUE        (spaces around = — .properties, .ini)
     *
     * Returns null if the line is not a key-value pair
     * (e.g., a YAML list item, a section header, a continuation line).
     */
    private KeyValue parseLine(String line) {
        // YAML format: key: value
        if (line.contains(": ")) {
            int idx = line.indexOf(": ");
            String key   = line.substring(0, idx).trim();
            String value = line.substring(idx + 2).trim();

            // Strip YAML string quotes if present
            value = stripQuotes(value);

            // Skip YAML structural lines (lists, maps, anchors)
            if (key.startsWith("-") || key.startsWith("&")
                    || key.startsWith("*") || value.isEmpty()) {
                return null;
            }
            return new KeyValue(key, value);
        }

        // KEY=VALUE format (.env, .properties, .ini)
        if (line.contains("=")) {
            int idx = line.indexOf('=');
            String key   = line.substring(0, idx).trim();
            String value = line.substring(idx + 1).trim();

            // Strip surrounding quotes: "value" or 'value'
            value = stripQuotes(value);

            // Reject lines where key looks like a URL or path (contains / or .)
            // to avoid false positives on lines like: jdbc.url=jdbc:mysql://...
            // We still check these for secrets below via pattern matching
            if (key.isEmpty()) return null;
            return new KeyValue(key, value);
        }

        return null; // Not a key-value line
    }

    private String stripQuotes(String value) {
        if (value.length() >= 2) {
            if ((value.startsWith("\"") && value.endsWith("\""))
                    || (value.startsWith("'")  && value.endsWith("'"))) {
                return value.substring(1, value.length() - 1);
            }
        }
        return value;
    }

    // ── Detection helpers ─────────────────────────────────────────────────────

    private boolean isDocumentationFile(String fileName) {
        String lower = fileName.toLowerCase();
        return DOCUMENTATION_SUFFIXES.stream()
                .anyMatch(lower::endsWith);
    }

    private boolean isComment(String line) {
        return line.startsWith("#")
                || line.startsWith("//")
                || line.startsWith("!")   // .properties comment style
                || line.startsWith(";");  // .ini comment style
    }

    private boolean isReference(String value) {
        return REFERENCE_PATTERNS.stream()
                .anyMatch(p -> p.matcher(value).matches());
    }

    private boolean isPlaceholder(String value) {
        return PLACEHOLDER_PATTERNS.stream()
                .anyMatch(p -> p.matcher(value).matches());
    }

    private boolean containsPlaceholderVerb(String value) {
        String lower = value.toLowerCase();
        String[] tokens = lower.split("[^a-z0-9]+");
        return Arrays.stream(tokens)
                .anyMatch(PLACEHOLDER_VERBS::contains);
    }

    private boolean isSensitiveKey(String key) {
        // Normalise: DB_PASSWORD → dbpassword, api-key → apikey
        String normalised = key.toLowerCase()
                .replace("_", "")
                .replace("-", "")
                .replace(".", "");
        return SENSITIVE_KEY_FRAGMENTS.stream()
                .anyMatch(f -> normalised.contains(f.replace("_", "")));
    }

    private boolean matchesKnownPattern(String value) {
        return SECRET_PATTERNS.stream()
                .anyMatch(p -> p.matcher(value).find());
    }

    private Confidence determineConfidence(
            boolean sensitiveKey,
            boolean knownPattern,
            boolean highEntropy,
            boolean mediumEntropy
    ) {
        if (knownPattern && sensitiveKey) return Confidence.HIGH;
        if (knownPattern)                 return Confidence.MEDIUM;
        if (sensitiveKey && highEntropy)  return Confidence.HIGH;
        if (sensitiveKey && mediumEntropy) return Confidence.MEDIUM;
        return null; // suppress
    }

    private String buildReason(
            String key,
            boolean sensitiveKey,
            boolean knownPattern,
            double entropy
    ) {
        StringBuilder sb = new StringBuilder();
        if (sensitiveKey) {
            sb.append("Config key '%s' suggests a credential. ".formatted(key));
        }
        if (knownPattern) {
            sb.append("Value matches a known secret token format. ");
        } else {
            sb.append("Shannon entropy %.2f bits/char indicates real credential data. "
                    .formatted(entropy));
        }
        return sb.toString();
    }

    private double shannonEntropy(String value) {
        if (value == null || value.isEmpty()) return 0.0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : value.toCharArray()) freq.merge(c, 1, Integer::sum);
        double entropy = 0.0;
        int length = value.length();
        for (int count : freq.values()) {
            double p = (double) count / length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private String redact(String value) {
        if (value.length() <= 6) return "***";
        return value.substring(0, 3) + "***" + value.substring(value.length() - 2);
    }

    // ── Supporting types ──────────────────────────────────────────────────────

    /** Simple parsed key-value pair from a config line. */
    private record KeyValue(String key, String value) {}
}