package com.minisast.core.report;

import com.minisast.core.model.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("HtmlReporter")
class HtmlReporterTest {

    private HtmlReporter reporter;
    private ScanResult   result;

    @BeforeEach
    void setUp() {
        reporter = new HtmlReporter();

        Finding finding = Finding.builder()
                .ruleId("JAVA-SQL-001")
                .ruleName("SQL Injection")
                .severity(Severity.CRITICAL)
                .confidence(Confidence.HIGH)
                .location(Location.of("src/UserService.java", 42))
                .message("User input flows into executeQuery")
                .remediation("Use PreparedStatement")
                .cwe("CWE-89")
                .owasp("A03:2021 - Injection")
                .build();

        result = ScanResult.of(
                "/project", 250L, "0.1.0", List.of(finding), 3, 100L
        );
    }

    @Test
    @DisplayName("getFormat returns 'html'")
    void format() {
        assertThat(reporter.getFormat()).isEqualTo("html");
    }

    @Test
    @DisplayName("Output starts with HTML doctype")
    void outputStartsWithDoctype() throws IOException {
        assertThat(reportAsString()).startsWith("<!DOCTYPE html>");
    }

    @Test
    @DisplayName("Output contains finding rule name")
    void containsRuleName() throws IOException {
        assertThat(reportAsString()).contains("SQL Injection");
    }

    @Test
    @DisplayName("Output contains severity label")
    void containsSeverityLabel() throws IOException {
        assertThat(reportAsString()).contains("CRITICAL");
    }

    @Test
    @DisplayName("Output contains target path")
    void containsTargetPath() throws IOException {
        assertThat(reportAsString()).contains("/project");
    }

    @Test
    @DisplayName("Output contains CWE reference")
    void containsCwe() throws IOException {
        assertThat(reportAsString()).contains("CWE-89");
    }

    @Test
    @DisplayName("Output contains remediation text")
    void containsRemediation() throws IOException {
        assertThat(reportAsString()).contains("PreparedStatement");
    }

    @Test
    @DisplayName("Empty scan produces valid HTML with no-findings message")
    void emptyScanHtml() throws IOException {
        ScanResult empty = ScanResult.of(
                "/empty", 10L, "0.1.0", List.of(), 0, 0L
        );
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        reporter.report(empty, out);
        String html = out.toString();

        assertThat(html).contains("<!DOCTYPE html>");
        assertThat(html).contains("No findings");
    }

    @Test
    @DisplayName("HTML is self-contained — no external script or link tags")
    void isSelfContained() throws IOException {
        String html = reportAsString();
        // No external CDN references
        assertThat(html).doesNotContain("cdn.jsdelivr.net");
        assertThat(html).doesNotContain("cdnjs.cloudflare.com");
        assertThat(html).doesNotContain("<link rel=\"stylesheet\" href=\"http");
        assertThat(html).doesNotContain("src=\"http");
    }

    private String reportAsString() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        reporter.report(result, out);
        return out.toString();
    }
}