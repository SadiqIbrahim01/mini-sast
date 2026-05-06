package com.minisast.core.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.minisast.core.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("JsonReporter")
class JsonReporterTest {

    private JsonReporter  reporter;
    private ObjectMapper  mapper;
    private ScanResult    result;

    @BeforeEach
    void setUp() {
        reporter = new JsonReporter();
        mapper   = new ObjectMapper();

        Finding finding = Finding.builder()
                .ruleId("JAVA-SQL-001")
                .ruleName("SQL Injection")
                .severity(Severity.CRITICAL)
                .confidence(Confidence.HIGH)
                .location(Location.of("src/UserService.java", 42,
                        42, "stmt.executeQuery(\"SELECT...\" + userId)"))
                .message("User input flows into executeQuery without parameterization")
                .remediation("Use PreparedStatement")
                .cwe("CWE-89")
                .owasp("A03:2021 - Injection")
                .build();

        result = ScanResult.of(
                "/path/to/project", 367L, "0.1.0",
                List.of(finding), 5, 200L
        );
    }

    @Test
    @DisplayName("getFormat returns 'json'")
    void format() {
        assertThat(reporter.getFormat()).isEqualTo("json");
    }

    @Test
    @DisplayName("Output is valid JSON")
    void producesValidJson() throws IOException {
        String json = reportAsString();
        assertThat(json).isNotEmpty();
        // Verify parseable
        JsonNode root = mapper.readTree(json);
        assertThat(root).isNotNull();
    }

    @Test
    @DisplayName("Output contains schema version")
    void containsSchemaVersion() throws IOException {
        JsonNode root = mapper.readTree(reportAsString());
        assertThat(root.get("schemaVersion").asText()).isEqualTo("1.0");
    }

    @Test
    @DisplayName("Output contains scan metadata")
    void containsScanMetadata() throws IOException {
        JsonNode root = mapper.readTree(reportAsString());

        assertThat(root.get("targetPath").asText()).isEqualTo("/path/to/project");
        assertThat(root.get("engineVersion").asText()).isEqualTo("0.1.0");
        assertThat(root.get("durationMs").asLong()).isEqualTo(367L);
        assertThat(root.get("scanId").asText()).isNotBlank();
        assertThat(root.get("scanTimestamp").asText()).isNotBlank();
    }

    @Test
    @DisplayName("Summary contains correct finding counts")
    void summaryContainsCounts() throws IOException {
        JsonNode summary = mapper.readTree(reportAsString()).get("summary");

        assertThat(summary.get("totalFindings").asInt()).isEqualTo(1);
        assertThat(summary.get("filesScanned").asInt()).isEqualTo(5);
        assertThat(summary.get("linesScanned").asLong()).isEqualTo(200L);
        assertThat(summary.get("findingsBySeverity").get("CRITICAL").asInt()).isEqualTo(1);
        assertThat(summary.get("findingsBySeverity").get("HIGH").asInt()).isEqualTo(0);
    }

    @Test
    @DisplayName("Findings array contains all findings")
    void findingsArrayComplete() throws IOException {
        JsonNode findings = mapper.readTree(reportAsString()).get("findings");

        assertThat(findings.isArray()).isTrue();
        assertThat(findings.size()).isEqualTo(1);
    }

    @Test
    @DisplayName("Finding contains all required fields")
    void findingHasRequiredFields() throws IOException {
        JsonNode finding = mapper.readTree(reportAsString())
                .get("findings").get(0);

        assertThat(finding.get("ruleId").asText()).isEqualTo("JAVA-SQL-001");
        assertThat(finding.get("ruleName").asText()).isEqualTo("SQL Injection");
        assertThat(finding.get("severity").asText()).isEqualTo("CRITICAL");
        assertThat(finding.get("confidence").asText()).isEqualTo("HIGH");
        assertThat(finding.get("cwe").asText()).isEqualTo("CWE-89");
        assertThat(finding.get("message").asText()).isNotBlank();
        assertThat(finding.get("remediation").asText()).isNotBlank();
    }

    @Test
    @DisplayName("Severity is serialized as string label not integer")
    void severityIsString() throws IOException {
        JsonNode finding = mapper.readTree(reportAsString())
                .get("findings").get(0);

        // Must be "CRITICAL" not 5
        assertThat(finding.get("severity").isTextual()).isTrue();
        assertThat(finding.get("severity").asText()).isEqualTo("CRITICAL");
    }

    @Test
    @DisplayName("Location contains file path and line number")
    void locationIsPresent() throws IOException {
        JsonNode location = mapper.readTree(reportAsString())
                .get("findings").get(0).get("location");

        assertThat(location.get("filePath").asText()).isEqualTo("src/UserService.java");
        assertThat(location.get("startLine").asInt()).isEqualTo(42);
    }

    @Test
    @DisplayName("Empty scan produces valid JSON with zero findings")
    void emptyScanProducesValidJson() throws IOException {
        ScanResult empty = ScanResult.of("/empty", 10L, "0.1.0",
                List.of(), 0, 0L);

        reporter = new JsonReporter();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        reporter.report(empty, out);

        JsonNode root = mapper.readTree(out.toString());
        assertThat(root.get("findings").isEmpty()).isTrue();
        assertThat(root.get("summary").get("totalFindings").asInt()).isZero();
    }

    private String reportAsString() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        reporter.report(result, out);
        return out.toString();
    }
}