package com.minisast.core.engine;

import com.minisast.core.model.Severity;
import com.minisast.core.model.ScanResult;
import com.minisast.core.parser.JavaLanguageParser;
import com.minisast.core.rules.RuleRegistry;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests — real parser, real rules, real fixture files.
 *
 * These tests validate end-to-end behaviour:
 *   fixture file → ScanEngine → ScanResult with expected findings
 *
 * They are deliberately named *IntegrationTest so Surefire's default
 * includes them. In Phase 6 we can split unit/integration with Maven profiles.
 */
@DisplayName("ScanEngine Integration")
class ScanEngineIntegrationTest {

    private ScanEngine engine;

    @BeforeEach
    void setUp() {
        engine = new ScanEngine(
                java.util.List.of(new JavaLanguageParser()),
                new RuleRegistry().enabled(),
                ScanConfiguration.defaults()
        );
    }

    // ── SQL Injection ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("Detects SQL injection in SqlInjectionSamples fixture")
    void detectsSqlInjection() throws IOException, URISyntaxException {
        ScanResult result = scanFixture("fixtures/vulnerable/SqlInjectionSamples.java");

        // 3 vulnerable methods, 2 safe ones
        assertThat(result.findings())
                .filteredOn(f -> f.ruleId().equals("JAVA-SQL-001"))
                .as("Should detect 3 SQL injection findings")
                .hasSize(3);
    }

    @Test
    @DisplayName("SQL injection findings are CRITICAL severity")
    void sqlInjectionIsCritical() throws IOException, URISyntaxException {
        ScanResult result = scanFixture("fixtures/vulnerable/SqlInjectionSamples.java");

        assertThat(result.findings())
                .filteredOn(f -> f.ruleId().equals("JAVA-SQL-001"))
                .extracting(f -> f.severity())
                .containsOnly(Severity.CRITICAL);
    }

    // ── Hardcoded Secrets ─────────────────────────────────────────────────────

    @Test
    @DisplayName("Detects hardcoded secrets in HardcodedSecretSamples fixture")
    void detectsHardcodedSecrets() throws IOException, URISyntaxException {
        ScanResult result = scanFixture("fixtures/vulnerable/HardcodedSecretSamples.java");

        assertThat(result.findings())
                .filteredOn(f -> f.ruleId().equals("JAVA-SEC-001"))
                .as("Should detect 5 hardcoded secret findings")
                .hasSize(5);
    }

    @Test
    @DisplayName("Does not flag placeholder templates as hardcoded secrets")
    void doesNotFlagPlaceholders() throws IOException, URISyntaxException {
        ScanResult result = scanFixture("fixtures/vulnerable/HardcodedSecretSamples.java");

        // None of the placeholder lines (28, 31, 34, 37, 40, 43, 46) should appear
        Set<Integer> placeholderLines = Set.of(28, 31, 34, 37, 40, 43, 46, 49, 52);

        assertThat(result.findings())
                .filteredOn(f -> f.ruleId().equals("JAVA-SEC-001"))
                .noneMatch(f -> placeholderLines.contains(f.location().startLine()));
    }

    @Test
    @DisplayName("Does not flag environment variable reads as hardcoded secrets")
    void doesNotFlagEnvVarReads() throws IOException, URISyntaxException {
        ScanResult result = scanFixture("fixtures/vulnerable/HardcodedSecretSamples.java");

        assertThat(result.findings())
                .filteredOn(f -> f.ruleId().equals("JAVA-SEC-001"))
                .noneMatch(f -> f.location().startLine() == 19);
    }

    @Test
    @DisplayName("Does not flag low-entropy sensitive names (test code pattern)")
    void doesNotFlagLowEntropyTestCode() throws IOException, URISyntaxException {
        ScanResult result = scanFixture("fixtures/vulnerable/HardcodedSecretSamples.java");

        // "mypassword" — sensitive name but low entropy, line 62
        assertThat(result.findings())
                .filteredOn(f -> f.ruleId().equals("JAVA-SEC-001"))
                .noneMatch(f -> f.location().startLine() == 62);
    }

    // ── Command Injection ─────────────────────────────────────────────────────

    @Test
    @DisplayName("Detects command injection in CommandInjectionSamples fixture")
    void detectsCommandInjection() throws IOException, URISyntaxException {
        ScanResult result = scanFixture("fixtures/vulnerable/CommandInjectionSamples.java");

        assertThat(result.findings())
                .filteredOn(f -> f.ruleId().equals("JAVA-CMD-001"))
                .as("Should detect 2 command injection findings")
                .hasSize(2);
    }

    @Test
    @DisplayName("Does not flag literal-only Runtime.exec calls")
    void doesNotFlagLiteralExec() throws IOException, URISyntaxException {
        ScanResult result = scanFixture("fixtures/vulnerable/CommandInjectionSamples.java");

        // literal exec is on line 18 — must not appear in findings
        assertThat(result.findings())
                .filteredOn(f -> f.ruleId().equals("JAVA-CMD-001"))
                .noneMatch(f -> f.location().startLine() == 18);
    }

    // ── Stats ──────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("ScanResult stats reflect actual finding counts")
    void statsAreAccurate() throws IOException, URISyntaxException {
        ScanResult result = scanFixture("fixtures/vulnerable/SqlInjectionSamples.java");

        assertThat(result.stats().filesScanned()).isEqualTo(1);
        assertThat(result.stats().totalFindings()).isEqualTo(result.findings().size());
        assertThat(result.stats().countBySeverity(Severity.CRITICAL))
                .isEqualTo(result.findings().stream()
                        .filter(f -> f.severity() == Severity.CRITICAL).count());
    }

    // ── Config file scanning ──────────────────────────────────────────────────────

    @Test
    @DisplayName("Detects secrets in .env file with real values")
    void detectsSecretsInEnvFile() throws IOException, URISyntaxException {
        ScanResult result = scanFixture("fixtures/vulnerable/secrets.env");

        assertThat(result.findings())
                .filteredOn(f -> f.ruleId().equals("CONFIG-SEC-001"))
                .as("Should detect all 5 hardcoded secrets in .env file")
                .hasSize(5);
    }

    @Test
    @DisplayName("Detects secrets in application.properties with real values")
    void detectsSecretsInPropertiesFile() throws IOException, URISyntaxException {
        ScanResult result = scanFixture(
                "fixtures/vulnerable/application-vulnerable.properties"
        );

        assertThat(result.findings())
                .filteredOn(f -> f.ruleId().equals("CONFIG-SEC-001"))
                .as("Should detect hardcoded secrets in properties file")
                .hasSizeGreaterThanOrEqualTo(3);
    }

    @Test
    @DisplayName("Does not flag safe application.properties using env var references")
    void doesNotFlagSafePropertiesFile() throws IOException, URISyntaxException {
        ScanResult result = scanFixture("fixtures/safe/application-safe.properties");

        assertThat(result.findings())
                .filteredOn(f -> f.ruleId().equals("CONFIG-SEC-001"))
                .as("Should produce zero findings for env-var-reference properties")
                .isEmpty();
    }

    @Test
    @DisplayName("Does not flag .env.example documentation file")
    void doesNotFlagEnvExampleFile() throws IOException, URISyntaxException {
        ScanResult result = scanFixture("fixtures/safe/example.env");

        assertThat(result.findings())
                .filteredOn(f -> f.ruleId().equals("CONFIG-SEC-001"))
                .as("Should produce zero findings for .env.example file")
                .isEmpty();
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    private ScanResult scanFixture(String resourcePath) throws IOException, URISyntaxException {
        var url = getClass().getClassLoader().getResource(resourcePath);
        assertThat(url)
                .as("Fixture not found on classpath: %s", resourcePath)
                .isNotNull();

        Path fixturePath = Paths.get(url.toURI());
        return engine.scan(fixturePath);
    }
}