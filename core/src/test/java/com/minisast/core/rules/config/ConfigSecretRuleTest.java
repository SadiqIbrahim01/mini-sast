package com.minisast.core.rules.config;

import com.minisast.core.model.Confidence;
import com.minisast.core.model.Severity;
import com.minisast.core.rules.RuleMatch;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ConfigSecretRule")
class ConfigSecretRuleTest {

    private ConfigSecretRule rule;

    @BeforeEach
    void setUp() { rule = new ConfigSecretRule(); }

    // ── Metadata ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Rule metadata is correctly defined")
    void metadata() {
        assertThat(rule.getId()).isEqualTo("CONFIG-SEC-001");
        assertThat(rule.getSeverity()).isEqualTo(Severity.CRITICAL);
        assertThat(rule.getCwe()).isEqualTo("CWE-798");
        assertThat(rule.isEnabled()).isTrue();
    }

    // ── Should detect ────────────────────────────────────────────────────────

    @Test
    @DisplayName("Detects high-entropy password in .env format")
    void detectsEnvPassword() {
        Optional<RuleMatch> match = analyze("DATABASE_PASSWORD=X9#mK2$pL8@vR4nQ");
        assertThat(match).isPresent();
        assertThat(match.get().confidence()).isEqualTo(Confidence.HIGH);
    }

    @Test
    @DisplayName("Detects high-entropy password in .properties format")
    void detectsPropertiesPassword() {
        Optional<RuleMatch> match = analyze("spring.datasource.password=X9#mK2$pL8@vR4nQ");
        assertThat(match).isPresent();
    }

    @Test
    @DisplayName("Detects high-entropy password in YAML format")
    void detectsYamlPassword() {
        Optional<RuleMatch> match = analyze("password: X9#mK2$pL8@vR4nQ");
        assertThat(match).isPresent();
    }

    @Test
    @DisplayName("Detects GitHub token by known pattern")
    void detectsGitHubToken() {
        Optional<RuleMatch> match = analyze(
                "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
        );
        assertThat(match).isPresent();
        assertThat(match.get().confidence()).isEqualTo(Confidence.HIGH);
    }

    // ── Reference patterns — must NOT be flagged ─────────────────────────────

    @ParameterizedTest(name = "Does not flag reference: {0}")
    @ValueSource(strings = {
            "DATABASE_PASSWORD=${DB_PASSWORD}",
            "DATABASE_PASSWORD=$DB_PASSWORD",
            "DATABASE_PASSWORD=#{systemEnvironment['DB_PASSWORD']}",
            "api.key=${API_KEY}",
            "jwt.secret=${JWT_SECRET}"
    })
    @DisplayName("Does not flag environment variable references")
    void doesNotFlagReferences(String line) {
        assertThat(analyze(line))
                .as("Should not flag reference line: %s", line)
                .isEmpty();
    }

    // ── Documentation files — must NOT be flagged ────────────────────────────

    @ParameterizedTest(name = "Ignores documentation file: {0}")
    @ValueSource(strings = {
            ".env.example",
            ".env.template",
            ".env.sample",
            "application.properties.example",
            "config.yml.dist",
            ".env.default"
    })
    @DisplayName("Does not scan documentation config files")
    void doesNotScanDocumentationFiles(String fileName) {
        // Even a real secret value should be ignored in a .example file
        Optional<RuleMatch> match = rule.analyzeLine(
                "DATABASE_PASSWORD=X9#mK2$pL8@vR4nQ",
                1, "/project/.env.example", fileName
        );
        assertThat(match)
                .as("Should ignore documentation file: %s", fileName)
                .isEmpty();
    }

    // ── Placeholder values — must NOT be flagged ─────────────────────────────

    @ParameterizedTest(name = "Does not flag placeholder value: {0}")
    @ValueSource(strings = {
            "DATABASE_PASSWORD={YOUR_PASSWORD_HERE}",
            "DATABASE_PASSWORD=<your-password>",
            "DATABASE_PASSWORD=REPLACE_WITH_YOUR_PASSWORD",
            "API_KEY=INSERT_YOUR_API_KEY_HERE",
            "API_KEY={YOUR_API_KEY}",
            "JWT_SECRET=[YOUR_JWT_SECRET]"
    })
    @DisplayName("Does not flag placeholder values")
    void doesNotFlagPlaceholders(String line) {
        assertThat(analyze(line))
                .as("Should not flag placeholder: %s", line)
                .isEmpty();
    }

    // ── Comments — must NOT be flagged ────────────────────────────────────────

    @ParameterizedTest(name = "Skips comment line: {0}")
    @ValueSource(strings = {
            "# DATABASE_PASSWORD=X9#mK2$pL8@vR4nQ",
            "// password=realSecretValue123456",
            "! api.key=sk-abc123def456ghi789jkl"
    })
    @DisplayName("Does not flag commented-out lines")
    void doesNotFlagComments(String line) {
        assertThat(analyze(line)).isEmpty();
    }

    // ── Empty values — must NOT be flagged ───────────────────────────────────

    @Test
    @DisplayName("Does not flag empty values")
    void doesNotFlagEmptyValue() {
        assertThat(analyze("DATABASE_PASSWORD=")).isEmpty();
        assertThat(analyze("DATABASE_PASSWORD= ")).isEmpty();
    }

    // ── Non-sensitive keys — must NOT be flagged ──────────────────────────────

    @Test
    @DisplayName("Does not flag non-sensitive key with non-matching value")
    void doesNotFlagNonSensitiveKey() {
        // Non-sensitive key, value has no known pattern
        assertThat(analyze("APP_NAME=my-application")).isEmpty();
        assertThat(analyze("SERVER_PORT=8080")).isEmpty();
    }

    // ── Redaction ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Redacts secret value in reported snippet")
    void redactsValueInSnippet() {
        Optional<RuleMatch> match = analyze("DATABASE_PASSWORD=X9#mK2$pL8@vR4nQ");
        assertThat(match).isPresent();
        String snippet = match.get().location().snippet();
        assertThat(snippet).doesNotContain("X9#mK2$pL8@vR4nQ");
        assertThat(snippet).contains("***");
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private Optional<RuleMatch> analyze(String line) {
        return rule.analyzeLine(line, 1, "/project/.env", ".env");
    }
}