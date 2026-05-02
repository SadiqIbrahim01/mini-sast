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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Detects hardcoded credentials and secrets in Java source code.
 *
 * Detection strategy — two complementary signals:
 *
 * SIGNAL 1: Sensitive variable name + non-empty string literal value
 *   String password = "hunter2";         → MATCH
 *   String apiKey   = "sk-abc123...";    → MATCH
 *   String password = System.getenv(…);  → no match (not a literal)
 *   String password = "";                → no match (empty literal)
 *
 * SIGNAL 2: String literal matching high-entropy / known secret patterns
 *   AWS access key:  "AKIAIOSFODNN7EXAMPLE"
 *   GitHub token:    "ghp_..."
 *   (Phase 2 covers common prefixes; entropy analysis in Phase 3)
 *
 * Both signals are checked. Either alone triggers a finding.
 *
 * CWE-798: Use of Hard-coded Credentials
 * OWASP A07:2021 — Identification and Authentication Failures
 */
public final class HardcodedSecretRule extends JavaAstRule {

    /** Variable names that strongly suggest a credential. Case-insensitive substring match. */
    private static final Set<String> SENSITIVE_NAME_FRAGMENTS = Set.of(
            "password", "passwd", "pwd",
            "secret",   "secretkey",
            "apikey",   "api_key",  "apitoken", "api_token",
            "token",    "accesstoken", "access_token",
            "privatekey", "private_key",
            "credential", "credentials",
            "authtoken",  "auth_token",
            "clientsecret", "client_secret",
            "dbpassword", "db_password", "dbpass",
            "connectionstring", "connection_string"
    );

    /** Known secret format patterns — prefix-based (fast, no entropy calc needed) */
    private static final List<Pattern> SECRET_PATTERNS = List.of(
            Pattern.compile("^AKIA[0-9A-Z]{16}$"),          // AWS Access Key ID
            Pattern.compile("^ghp_[a-zA-Z0-9]{36}$"),       // GitHub Personal Access Token
            Pattern.compile("^ghs_[a-zA-Z0-9]{36}$"),       // GitHub Actions Token
            Pattern.compile("^sk-[a-zA-Z0-9]{32,}$"),       // OpenAI / Stripe secret key prefix
            Pattern.compile("^eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$"), // JWT
            Pattern.compile("^-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----") // PEM private key
    );

    /** Minimum length for a literal to be considered a real secret (not a placeholder) */
    private static final int MIN_SECRET_LENGTH = 8;

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
                "A07:2021 – Identification and Authentication Failures",
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

        /**
         * Visits field declarations:
         *   private String apiKey = "sk-live-abc123";
         *   static final String DB_PASS = "hunter2";
         */
        @Override
        public void visit(FieldDeclaration field, Void arg) {
            super.visit(field, arg);

            for (VariableDeclarator var : field.getVariables()) {
                var.getInitializer().ifPresent(init -> {
                    if (init instanceof StringLiteralExpr literal) {
                        checkVariable(var.getNameAsString(), literal, var.getBegin()
                                .map(p -> p.line).orElse(0));
                    }
                });
            }
        }

        /**
         * Visits local variable declarations:
         *   String password = "hunter2";
         *   var token = "ghp_abc...";
         */
        @Override
        public void visit(VariableDeclarationExpr varDecl, Void arg) {
            super.visit(varDecl, arg);

            for (VariableDeclarator var : varDecl.getVariables()) {
                var.getInitializer().ifPresent(init -> {
                    if (init instanceof StringLiteralExpr literal) {
                        checkVariable(var.getNameAsString(), literal, var.getBegin()
                                .map(p -> p.line).orElse(0));
                    }
                });
            }
        }

        /**
         * Visits assignment expressions:
         *   this.password = "hunter2";
         *   config.apiKey = "sk-abc...";
         */
        @Override
        public void visit(AssignExpr assign, Void arg) {
            super.visit(assign, arg);

            if (assign.getValue() instanceof StringLiteralExpr literal) {
                String targetName = extractName(assign.getTarget());
                if (targetName != null) {
                    checkVariable(targetName, literal, assign.getBegin()
                            .map(p -> p.line).orElse(0));
                }
            }
        }

        // ── Helpers ──────────────────────────────────────────────────────────

        private void checkVariable(String varName, StringLiteralExpr literal, int line) {
            String value = literal.asString();

            // Ignore empty strings and obvious placeholders
            if (value.isBlank() || value.length() < MIN_SECRET_LENGTH) {
                return;
            }

            // Ignore obvious placeholders
            if (isPlaceholder(value)) {
                return;
            }

            boolean sensitiveByName    = isSensitiveName(varName);
            boolean sensitiveByPattern = matchesSecretPattern(value);

            if (!sensitiveByName && !sensitiveByPattern) {
                return;
            }

            Confidence confidence = (sensitiveByName && sensitiveByPattern)
                    ? Confidence.HIGH
                    : Confidence.MEDIUM;

            String reason = sensitiveByName
                    ? "Variable name '%s' suggests a credential".formatted(varName)
                    : "Value matches known secret format";

            Location location = new Location(filePath, line, line, 0, 0,
                    varName + " = \"" + redact(value) + "\"");

            matches.add(new RuleMatch(
                    getId(),
                    location,
                    "%s with hardcoded string value. Hardcoded secrets are permanently "
                            .formatted(reason) +
                            "exposed if the source code is ever leaked or committed to a repository.",
                    confidence
            ));
        }

        private boolean isSensitiveName(String name) {
            String lower = name.toLowerCase().replace("-", "").replace("_", "");
            return SENSITIVE_NAME_FRAGMENTS.stream()
                    .anyMatch(fragment -> lower.contains(fragment.replace("_", "")));
        }

        private boolean matchesSecretPattern(String value) {
            return SECRET_PATTERNS.stream()
                    .anyMatch(p -> p.matcher(value).find());
        }

        private boolean isPlaceholder(String value) {
            String lower = value.toLowerCase();
            return lower.contains("placeholder")
                    || lower.contains("changeme")
                    || lower.contains("your_")
                    || lower.contains("example")
                    || lower.contains("xxx")
                    || lower.contains("<") && lower.contains(">")
                    || lower.equals("password")
                    || lower.equals("secret")
                    || lower.equals("token");
        }

        /**
         * Redact the middle of a secret value for safe display in reports.
         * "sk-live-abc123def456" → "sk-live-a***56"
         */
        private String redact(String value) {
            if (value.length() <= 6) return "***";
            return value.substring(0, 3) + "***" + value.substring(value.length() - 2);
        }

        private String extractName(Expression target) {
            if (target instanceof NameExpr n)               return n.getNameAsString();
            if (target instanceof FieldAccessExpr f)        return f.getNameAsString();
            return null;
        }
    }
}