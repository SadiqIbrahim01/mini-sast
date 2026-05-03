package com.minisast.core.rules.java;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.minisast.core.model.Confidence;
import com.minisast.core.model.Severity;
import com.minisast.core.rules.RuleMatch;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("HardcodedSecretRule")
class HardcodedSecretRuleTest {

    private HardcodedSecretRule rule;

    @BeforeEach
    void setUp() { rule = new HardcodedSecretRule(); }

    // ── Rule metadata ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("Rule metadata is correctly defined")
    void ruleMetadata() {
        assertThat(rule.getId()).isEqualTo("JAVA-SEC-001");
        assertThat(rule.getSeverity()).isEqualTo(Severity.HIGH);
        assertThat(rule.getCwe()).isEqualTo("CWE-798");
        assertThat(rule.getLanguage()).isEqualTo("java");
        assertThat(rule.isEnabled()).isTrue();
    }

    // ── Should detect ────────────────────────────────────────────────────────

    @Test
    @DisplayName("Detects high-entropy value with sensitive variable name")
    void detectsHighEntropyWithSensitiveName() {
        String code = """
            class T {
                String apiKey = "sk-abc123def456ghi789jkl012345";
            }
            """;
        List<RuleMatch> matches = analyze(code);
        assertThat(matches).hasSize(1);
        assertThat(matches.get(0).confidence()).isEqualTo(Confidence.HIGH);
    }

    @Test
    @DisplayName("Detects GitHub token by known pattern")
    void detectsGitHubToken() {
        String code = """
            class T {
                void m() {
                    String token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
                }
            }
            """;
        assertThat(analyze(code)).hasSize(1);
    }

    @Test
    @DisplayName("Detects JWT token by known pattern")
    void detectsJwtToken() {
        String code = """
            class T {
                String auth = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456";
            }
            """;
        assertThat(analyze(code)).hasSize(1);
    }

    // ── Placeholder detection ────────────────────────────────────────────────

    @ParameterizedTest(name = "Does not flag placeholder: {0}")
    @ValueSource(strings = {
            "{YOUR_API_KEY_HERE}",
            "{YOUR_PASSWORD_HERE}",
            "${DB_PASSWORD}",
            "${API_KEY}",
            "[INSERT_TOKEN_HERE]",
            "[YOUR_KEY]",
            "REPLACE_WITH_YOUR_API_KEY",
            "INSERT_SECRET_HERE",
            "ADD_YOUR_TOKEN_HERE",
            "YOUR_API_KEY_GOES_HERE"
    })
    @DisplayName("Does not flag placeholder patterns")
    void doesNotFlagPlaceholders(String placeholder) {
        String code = """
            class T {
                String apiKey = "%s";
            }
            """.formatted(placeholder);
        assertThat(analyze(code))
                .as("Should not flag placeholder: %s", placeholder)
                .isEmpty();
    }

    @Test
    @DisplayName("Does not flag repeated character strings")
    void doesNotFlagRepeatedChars() {
        String code = """
            class T {
                String password = "xxxxxxxxxxxxxxxx";
            }
            """;
        assertThat(analyze(code)).isEmpty();
    }

    @Test
    @DisplayName("Does not flag sequential character strings")
    void doesNotFlagSequentialChars() {
        String code = """
            class T {
                String password = "abcdefghijklmnop";
            }
            """;
        assertThat(analyze(code)).isEmpty();
    }

    @Test
    @DisplayName("Does not flag environment variable reads")
    void doesNotFlagEnvVarReads() {
        String code = """
            class T {
                String password = System.getenv("DB_PASSWORD");
            }
            """;
        assertThat(analyze(code)).isEmpty();
    }

    @Test
    @DisplayName("Does not flag low-entropy value with sensitive name")
    void doesNotFlagLowEntropySensitiveName() {
        String code = """
            class T {
                String password = "mypassword";
            }
            """;
        // "mypassword" — sensitive name but low entropy, common in test code
        assertThat(analyze(code)).isEmpty();
    }

    @Test
    @DisplayName("Does not flag non-sensitive name with non-matching value")
    void doesNotFlagNonSensitiveName() {
        String code = """
            class T {
                String description = "this is just a description string here";
            }
            """;
        assertThat(analyze(code)).isEmpty();
    }

    // ── Redaction ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Reported snippet redacts the secret value")
    void redactsSecretInSnippet() {
        String code = """
            class T {
                String apiKey = "sk-realSecretValue12345678901234";
            }
            """;
        List<RuleMatch> matches = analyze(code);
        assertThat(matches).hasSize(1);

        // Snippet must not contain the full secret
        String snippet = matches.get(0).location().snippet();
        assertThat(snippet).doesNotContain("realSecretValue");
        assertThat(snippet).contains("***");
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private List<RuleMatch> analyze(String code) {
        CompilationUnit cu = StaticJavaParser.parse(code);
        return rule.analyze(cu, "Test.java");
    }
}