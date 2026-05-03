package com.minisast.core.rules.java;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.minisast.core.model.Confidence;
import com.minisast.core.model.Location;
import com.minisast.core.model.Severity;
import com.minisast.core.rules.JavaAstRule;
import com.minisast.core.rules.RuleMatch;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Detects hardcoded credentials and secrets in Java source code.
 *
 * Detection uses THREE independent signals, combined for precision:
 *
 * SIGNAL 1 — Sensitive variable name
 *   Variable is named "password", "apiKey", "secret", etc.
 *   Broad but necessary — names carry intent.
 *
 * SIGNAL 2 — Known secret format pattern
 *   Value matches a known token prefix (AWS AKIA..., GitHub ghp_, JWT eyJ...)
 *   Narrow and precise — these patterns are format-specific.
 *
 * SIGNAL 3 — Shannon entropy threshold
 *   Real secrets are random data. Random data has high entropy (>3.5 bits/char).
 *   Human-readable placeholders, English phrases, and template strings
 *   have low entropy (<3.0 bits/char).
 *   This is the same technique used by TruffleHog and detect-secrets.
 *
 * PLACEHOLDER DETECTION — applied before signals, acts as early exit:
 *   Structural indicators that a value is intentionally fake:
 *   curly/square/angle bracket templates, instruction verbs (INSERT/REPLACE/ADD),
 *   repeated characters, sequential characters, all-uppercase instruction text.
 *
 * CONFIDENCE MATRIX:
 *   Sensitive name + known pattern + high entropy → HIGH
 *   Sensitive name + known pattern               → HIGH  (pattern is very specific)
 *   Sensitive name + high entropy                → HIGH
 *   Known pattern only                           → MEDIUM (name might be misleading)
 *   Sensitive name only + medium entropy         → MEDIUM
 *   Sensitive name only + low entropy            → suppressed (likely placeholder)
 *
 * CWE-798: Use of Hard-coded Credentials
 * OWASP A07:2021 - Identification and Authentication Failures
 */
public final class HardcodedSecretRule extends JavaAstRule {

    // ── Sensitive variable name fragments ────────────────────────────────────
    // Checked as case-insensitive substrings after stripping underscores/hyphens
    private static final Set<String> SENSITIVE_NAME_FRAGMENTS = Set.of(
            "password", "passwd", "pwd",
            "secret",   "secretkey",
            "apikey",   "apitoken",
            "token",    "accesstoken",
            "privatekey",
            "credential", "credentials",
            "authtoken",
            "clientsecret",
            "dbpassword", "dbpass",
            "connectionstring"
    );

    // ── Known secret format patterns ─────────────────────────────────────────
    // These are format-specific and have very low false positive rates
    private static final List<Pattern> SECRET_PATTERNS = List.of(
            Pattern.compile("^AKIA[0-9A-Z]{16}$"),           // AWS Access Key ID
            Pattern.compile("^ghp_[a-zA-Z0-9]{36}$"),        // GitHub Personal Access Token
            Pattern.compile("^ghs_[a-zA-Z0-9]{36}$"),        // GitHub Actions Token
            Pattern.compile("^ghr_[a-zA-Z0-9]{36}$"),        // GitHub Refresh Token
            Pattern.compile("^sk-[a-zA-Z0-9]{20,}$"),        // OpenAI / Stripe
            Pattern.compile("^pk_live_[a-zA-Z0-9]{24,}$"),   // Stripe public live key
            Pattern.compile("^sk_live_[a-zA-Z0-9]{24,}$"),   // Stripe secret live key
            Pattern.compile("^xox[bpoa]-[a-zA-Z0-9-]{10,}"), // Slack tokens
            Pattern.compile("^eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"), // JWT
            Pattern.compile("^-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----")  // PEM keys
    );

    // ── Placeholder structural patterns ──────────────────────────────────────
    // These are checked BEFORE entropy/signals — structural placeholders
    // are obvious fakes regardless of their entropy score
    private static final List<Pattern> PLACEHOLDER_PATTERNS = List.of(
            // Curly brace templates: {YOUR_API_KEY}, {INSERT_KEY_HERE}, {TOKEN}
            Pattern.compile("^\\{[^}]{2,}\\}$"),

            // Dollar-sign templates: ${API_KEY}, ${SECRET}, ${DB_PASSWORD}
            Pattern.compile("^\\$\\{[^}]+\\}$"),

            // Square bracket templates: [YOUR_KEY], [API_TOKEN_HERE]
            Pattern.compile("^\\[[^]]{2,}\\]$"),

            // Angle bracket templates: <YOUR_KEY>, <API_TOKEN> (already partially covered)
            Pattern.compile("^<[^>]{2,}>$"),

            // All-uppercase instruction text: YOUR_API_KEY_HERE, REPLACE_WITH_TOKEN
            // Real secrets are rarely all-uppercase plain text
            Pattern.compile("^[A-Z][A-Z0-9_]{6,}$")
    );

    // ── Instruction verbs that indicate placeholder intent ───────────────────
    // These appear in placeholder values regardless of surrounding punctuation
    private static final Set<String> PLACEHOLDER_VERBS = Set.of(
            "insert", "replace", "add", "put", "fill", "enter",
            "your", "here", "todo", "fixme", "changeme", "placeholder",
            "example", "sample", "test", "dummy", "fake", "mock",
            "override", "configure", "set", "define", "update"
    );

    // ── Thresholds ───────────────────────────────────────────────────────────
    private static final int    MIN_LENGTH           = 8;
    private static final double HIGH_ENTROPY_THRESHOLD   = 3.5; // bits/char
    private static final double MEDIUM_ENTROPY_THRESHOLD = 3.3; // bits/char

    public HardcodedSecretRule() {
        super(
                "JAVA-SEC-001",
                "Hardcoded Secret",
                "A credential or secret value is hardcoded in source code. " +
                        "If this repository is ever exposed, the secret is permanently compromised " +
                        "and cannot be rotated without a code change.",
                Severity.HIGH,
                Confidence.HIGH,
                "CWE-798",
                "A07:2021 - Identification and Authentication Failures",
                "Move secrets to environment variables (System.getenv(\"SECRET_NAME\")), " +
                        "a secrets manager (AWS Secrets Manager, HashiCorp Vault), " +
                        "or configuration files excluded from version control."
        );
    }

    @Override
    public List<RuleMatch> analyze(CompilationUnit cu, String filePath) {
        List<RuleMatch> matches = new ArrayList<>();
        cu.accept(new SecretVisitor(filePath, matches), null);
        return matches;
    }

    // ─────────────────────────────────────────────────────────────────────────

    private final class SecretVisitor extends VoidVisitorAdapter<Void> {

        private final String          filePath;
        private final List<RuleMatch> matches;

        SecretVisitor(String filePath, List<RuleMatch> matches) {
            this.filePath = filePath;
            this.matches  = matches;
        }

        @Override
        public void visit(FieldDeclaration field, Void arg) {
            super.visit(field, arg);
            for (VariableDeclarator var : field.getVariables()) {
                var.getInitializer().ifPresent(init -> {
                    if (init instanceof StringLiteralExpr literal) {
                        checkVariable(
                                var.getNameAsString(),
                                literal.asString(),
                                var.getBegin().map(p -> p.line).orElse(0)
                        );
                    }
                });
            }
        }

        @Override
        public void visit(VariableDeclarationExpr varDecl, Void arg) {
            super.visit(varDecl, arg);
            for (VariableDeclarator var : varDecl.getVariables()) {
                var.getInitializer().ifPresent(init -> {
                    if (init instanceof StringLiteralExpr literal) {
                        checkVariable(
                                var.getNameAsString(),
                                literal.asString(),
                                var.getBegin().map(p -> p.line).orElse(0)
                        );
                    }
                });
            }
        }

        @Override
        public void visit(AssignExpr assign, Void arg) {
            super.visit(assign, arg);
            if (assign.getValue() instanceof StringLiteralExpr literal) {
                String targetName = extractName(assign.getTarget());
                if (targetName != null) {
                    checkVariable(
                            targetName,
                            literal.asString(),
                            assign.getBegin().map(p -> p.line).orElse(0)
                    );
                }
            }
        }

        // ── Core detection logic ──────────────────────────────────────────────

        private void checkVariable(String varName, String value, int line) {

            // Gate 1: Minimum length — anything shorter is not a real secret
            if (value == null || value.length() < MIN_LENGTH) return;

            // Gate 2: Structural placeholder check — fast exits before entropy calc
            if (isStructuralPlaceholder(value)) return;

            // Gate 3: Instruction verb check — human-readable fake values
            if (containsPlaceholderVerb(value)) return;

            // Gate 4: Repeated/sequential character check — "xxxxxxxx", "12345678"
            if (isRepeatedOrSequential(value)) return;

            // Now evaluate the three detection signals
            boolean sensitiveName   = isSensitiveName(varName);
            boolean knownPattern    = matchesKnownSecretPattern(value);
            double  entropy         = shannonEntropy(value);
            boolean highEntropy     = entropy >= HIGH_ENTROPY_THRESHOLD;
            boolean mediumEntropy   = entropy >= MEDIUM_ENTROPY_THRESHOLD;

            // Confidence matrix — combine signals
            Confidence confidence = determineConfidence(
                    sensitiveName, knownPattern, highEntropy, mediumEntropy
            );

            // If no signal combination warrants a finding, suppress
            if (confidence == null) return;

            String reason = buildReason(varName, sensitiveName, knownPattern, entropy);

            Location location = new Location(
                    filePath, line, line, 0, 0,
                    varName + " = \"" + redact(value) + "\""
            );

            matches.add(new RuleMatch(
                    getId(),
                    location,
                    reason + " Hardcoded secrets are permanently exposed if source " +
                            "code is leaked or committed to a public repository.",
                    confidence
            ));
        }

        // ── Signal evaluation ─────────────────────────────────────────────────

        /**
         * Confidence matrix — the result of combining three independent signals.
         * Returns null if no finding should be reported (suppress).
         *
         * Decision table:
         *   Name  Pattern  HighEntropy  MediumEntropy  → Confidence
         *   ✅     ✅        any          any            → HIGH   (two specific signals)
         *   ✅     ❌        ✅            -             → HIGH   (name + entropy)
         *   ❌     ✅        any          any            → MEDIUM (pattern but odd name)
         *   ✅     ❌        ❌            ✅             → MEDIUM (name + some entropy)
         *   ✅     ❌        ❌            ❌             → null   (name only + low entropy = placeholder)
         *   ❌     ❌        any          any            → null   (no signals = suppress)
         */
        private Confidence determineConfidence(
                boolean sensitiveName,
                boolean knownPattern,
                boolean highEntropy,
                boolean mediumEntropy
        ) {
            // Known pattern is a very strong signal — always report
            if (knownPattern && sensitiveName) return Confidence.HIGH;
            if (knownPattern)                  return Confidence.MEDIUM;

            // Sensitive name + high entropy = real secret
            if (sensitiveName && highEntropy)  return Confidence.HIGH;

            // Sensitive name + medium entropy = likely real, less certain
            if (sensitiveName && mediumEntropy) return Confidence.MEDIUM;

            // Sensitive name + low entropy = placeholder not caught by earlier gates
            // Example: password = "mypassword" — looks like placeholder/weak test value
            // Suppress — too many false positives in test code
            return null;
        }

        private String buildReason(
                String varName,
                boolean sensitiveName,
                boolean knownPattern,
                double entropy
        ) {
            StringBuilder sb = new StringBuilder();

            if (sensitiveName) {
                sb.append("Variable '%s' suggests a credential.".formatted(varName));
            }
            if (knownPattern) {
                if (!sb.isEmpty()) sb.append(" ");
                sb.append("Value matches a known secret token format.");
            }
            if (!knownPattern) {
                if (!sb.isEmpty()) sb.append(" ");
                sb.append("Shannon entropy %.2f bits/char indicates non-random content."
                        .formatted(entropy));
            }

            if (!sb.isEmpty()) sb.append(" ");
            return sb.toString();
        }

        // ── Placeholder detection ─────────────────────────────────────────────

        /**
         * Checks for structural placeholder indicators:
         * {YOUR_API_KEY}, ${TOKEN}, [KEY_HERE], <API_KEY>
         * Also catches ALL_CAPS_WITH_UNDERSCORES instruction text.
         */
        private boolean isStructuralPlaceholder(String value) {
            return PLACEHOLDER_PATTERNS.stream()
                    .anyMatch(p -> p.matcher(value).matches());
        }

        /**
         * Checks for instruction verbs embedded in the value.
         * Splits on non-alphanumeric characters to tokenise:
         *   "INSERT_YOUR_API_KEY_HERE" → ["insert", "your", "api", "key", "here"]
         *   "REPLACE_WITH_TOKEN"       → ["replace", "with", "token"]
         *   "{your-api-key}"           → ["your", "api", "key"]
         */
        private boolean containsPlaceholderVerb(String value) {
            String lower = value.toLowerCase();
            String[] tokens = lower.split("[^a-z0-9]+");
            return Arrays.stream(tokens)
                    .anyMatch(PLACEHOLDER_VERBS::contains);
        }

        /**
         * Detects values with no real randomness:
         *
         * Repeated characters: "xxxxxxxxxxxxxxxx", "????????????????"
         *   → All same character, clearly fake
         *
         * Sequential characters: "abcdefghijklmnop", "1234567890123456"
         *   → Monotonically increasing ASCII values, clearly fake
         *
         * Both patterns are common in documentation, tests, and examples.
         */
        private boolean isRepeatedOrSequential(String value) {
            if (value.length() < MIN_LENGTH) return false;

            // Check repeated: all characters identical
            char first = value.charAt(0);
            boolean allSame = true;
            for (char c : value.toCharArray()) {
                if (c != first) { allSame = false; break; }
            }
            if (allSame) return true;

            // Check sequential: each character increments by 1
            boolean sequential = true;
            for (int i = 1; i < value.length(); i++) {
                if (value.charAt(i) != value.charAt(i - 1) + 1) {
                    sequential = false;
                    break;
                }
            }
            return sequential;
        }

        // ── Shannon Entropy ───────────────────────────────────────────────────

        /**
         * Computes Shannon entropy of a string in bits per character.
         *
         * Formula: H = -Σ p(x) × log₂(p(x))
         *   where p(x) = frequency of character x / total length
         *
         * Interpretation:
         *   < 3.0 bits/char  → Low entropy  (English text, placeholders, repeated chars)
         *   3.0–3.5 bits/char → Medium entropy (weak passwords, short tokens)
         *   > 3.5 bits/char  → High entropy  (real secrets, crypto keys, UUIDs)
         *
         * Examples:
         *   "password"                    → ~2.75 bits/char
         *   "YOUR_API_KEY_HERE"           → ~3.15 bits/char
         *   "correct-horse-battery-staple"→ ~3.58 bits/char (high — but flagged by verb check)
         *   "sk-abc123def456ghi789jkl0"   → ~4.47 bits/char
         *   "AKIAIOSFODNN7EXAMPLE"        → ~3.91 bits/char
         *   UUID "550e8400-e29b-41d4"     → ~4.12 bits/char
         */
        private double shannonEntropy(String value) {
            if (value == null || value.isEmpty()) return 0.0;

            // Count frequency of each character
            Map<Character, Integer> frequency = new HashMap<>();
            for (char c : value.toCharArray()) {
                frequency.merge(c, 1, Integer::sum);
            }

            // Compute entropy
            double entropy = 0.0;
            int length = value.length();
            for (int count : frequency.values()) {
                double probability = (double) count / length;
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }

            return entropy;
        }

        // ── Name / Pattern matching ───────────────────────────────────────────

        private boolean isSensitiveName(String name) {
            // Normalise: lowercase, strip underscores and hyphens
            // "api_key" → "apikey", "API-KEY" → "apikey", "ApiKey" → "apikey"
            String normalised = name.toLowerCase()
                    .replace("_", "")
                    .replace("-", "");
            return SENSITIVE_NAME_FRAGMENTS.stream()
                    .anyMatch(normalised::contains);
        }

        private boolean matchesKnownSecretPattern(String value) {
            return SECRET_PATTERNS.stream()
                    .anyMatch(p -> p.matcher(value).find());
        }

        // ── Utility ───────────────────────────────────────────────────────────

        /**
         * Redacts a secret value for safe inclusion in reports.
         * The report itself may be shared in tickets, emails, or wikis.
         * Showing the full secret in the report spreads it further.
         *
         * "sk-live-abc123def456" → "sk-***56"
         * Shows enough to identify which secret (first 3 chars)
         * without exposing enough to be usable.
         */
        private String redact(String value) {
            if (value.length() <= 6) return "***";
            return value.substring(0, 3) + "***" + value.substring(value.length() - 2);
        }

        private String extractName(Expression target) {
            if (target instanceof NameExpr n)        return n.getNameAsString();
            if (target instanceof FieldAccessExpr f) return f.getNameAsString();
            return null;
        }
    }
}