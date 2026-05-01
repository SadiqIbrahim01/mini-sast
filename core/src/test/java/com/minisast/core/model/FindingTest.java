package com.minisast.core.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

@DisplayName("Finding")
class FindingTest {

    private static final Location LOCATION = Location.of("src/main/Foo.java", 42);

    @Test
    @DisplayName("Builder creates valid finding with all required fields")
    void builderHappyPath() {
        Finding finding = Finding.builder()
                .ruleId("JAVA-SQL-001")
                .ruleName("SQL Injection")
                .severity(Severity.CRITICAL)
                .confidence(Confidence.HIGH)
                .location(LOCATION)
                .message("User input flows into executeQuery without parameterization")
                .cwe("CWE-89")
                .owasp("A03:2021")
                .remediation("Use PreparedStatement with parameterized queries")
                .build();

        assertThat(finding.id()).isNotNull().isNotBlank();
        assertThat(finding.ruleId()).isEqualTo("JAVA-SQL-001");
        assertThat(finding.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(finding.confidence()).isEqualTo(Confidence.HIGH);
        assertThat(finding.location().startLine()).isEqualTo(42);
        assertThat(finding.detectedAt()).isNotNull();
    }

    @Test
    @DisplayName("Each build() call generates a unique ID")
    void uniqueIds() {
        Finding f1 = minimalFinding();
        Finding f2 = minimalFinding();
        assertThat(f1.id()).isNotEqualTo(f2.id());
    }

    @Test
    @DisplayName("Builder requires ruleId")
    void requiresRuleId() {
        assertThatThrownBy(() ->
                Finding.builder()
                        .severity(Severity.HIGH)
                        .location(LOCATION)
                        .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ruleId");
    }

    @Test
    @DisplayName("Builder requires severity")
    void requiresSeverity() {
        assertThatThrownBy(() ->
                Finding.builder()
                        .ruleId("JAVA-001")
                        .location(LOCATION)
                        .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("severity");
    }

    @Test
    @DisplayName("ScanResult findings list is immutable")
    void scanResultFindingsAreImmutable() {
        ScanResult result = ScanResult.of("./", 100L, "0.1.0",
                List.of(minimalFinding()), 1, 50L);

        assertThatThrownBy(() -> result.findings().add(minimalFinding()))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("ScanResult computes stats from findings")
    void scanResultComputesStats() {
        List<Finding> findings = List.of(
                findingWithSeverity(Severity.CRITICAL),
                findingWithSeverity(Severity.CRITICAL),
                findingWithSeverity(Severity.HIGH),
                findingWithSeverity(Severity.LOW)
        );

        ScanResult result = ScanResult.of("./", 0L, "0.1.0", findings, 5, 100L);

        assertThat(result.stats().totalFindings()).isEqualTo(4);
        assertThat(result.stats().countBySeverity(Severity.CRITICAL)).isEqualTo(2L);
        assertThat(result.stats().countBySeverity(Severity.HIGH)).isEqualTo(1L);
        assertThat(result.stats().countBySeverity(Severity.MEDIUM)).isEqualTo(0L);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Finding minimalFinding() {
        return Finding.builder()
                .ruleId("JAVA-001")
                .severity(Severity.HIGH)
                .location(LOCATION)
                .build();
    }

    private Finding findingWithSeverity(Severity severity) {
        return Finding.builder()
                .ruleId("JAVA-001")
                .severity(severity)
                .location(LOCATION)
                .build();
    }
}