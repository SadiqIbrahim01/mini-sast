package com.minisast.core.report;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.minisast.core.model.*;

import java.io.IOException;
import java.io.OutputStream;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Produces a structured JSON report suitable for:
 *   - CI/CD pipeline consumption (jq, GitHub Actions, etc.)
 *   - Dashboard ingestion
 *   - Long-term finding storage and trend analysis
 *   - API responses (Phase 7)
 *
 * Uses a dedicated DTO layer (private inner records) rather than
 * serializing domain objects directly. This decouples the JSON schema
 * from internal implementation — if Finding gains a new field, the
 * JSON output only changes when we deliberately update the DTO.
 *
 * Schema version is included in every output so consumers can handle
 * format evolution gracefully.
 */
public final class JsonReporter implements Reporter {

    private static final String SCHEMA_VERSION = "1.0";

    private final ObjectMapper mapper;

    public JsonReporter() {
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(SerializationFeature.INDENT_OUTPUT)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @Override
    public String getFormat() { return "json"; }

    @Override
    public void report(ScanResult result, OutputStream output) throws IOException {
        mapper.writeValue(output, toDto(result));
    }

    // ── DTO conversion ────────────────────────────────────────────────────────

    private ScanReportDto toDto(ScanResult result) {
        List<FindingDto> findings = result.findings().stream()
                .sorted(Comparator.comparingInt(f -> -f.severity().getLevel()))
                .map(this::toFindingDto)
                .collect(Collectors.toList());

        Map<String, Long> bySeverity = new LinkedHashMap<>();
        for (Severity s : new Severity[]{
                Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFO}) {
            bySeverity.put(s.getLabel(), result.stats().countBySeverity(s));
        }

        SummaryDto summary = new SummaryDto(
                result.stats().filesScanned(),
                result.stats().linesScanned(),
                result.stats().totalFindings(),
                bySeverity
        );

        return new ScanReportDto(
                SCHEMA_VERSION,
                result.scanId(),
                result.targetPath(),
                result.scanTimestamp().toString(),
                result.durationMs(),
                result.engineVersion(),
                summary,
                findings
        );
    }

    private FindingDto toFindingDto(Finding f) {
        LocationDto location = new LocationDto(
                f.location().filePath(),
                f.location().startLine(),
                f.location().endLine(),
                f.location().snippet().isBlank() ? null : f.location().snippet()
        );

        return new FindingDto(
                f.id(),
                f.ruleId(),
                f.ruleName(),
                f.severity().getLabel(),
                f.confidence().getLabel(),
                f.cwe().isBlank()         ? null : f.cwe(),
                f.owasp().isBlank()        ? null : f.owasp(),
                location,
                f.message(),
                f.remediation().isBlank()  ? null : f.remediation(),
                f.detectedAt().toString()
        );
    }

    // ── DTOs — stable JSON schema ─────────────────────────────────────────────

    private record ScanReportDto(
            String        schemaVersion,
            String        scanId,
            String        targetPath,
            String        scanTimestamp,
            long          durationMs,
            String        engineVersion,
            SummaryDto    summary,
            List<FindingDto> findings
    ) {}

    private record SummaryDto(
            int              filesScanned,
            long             linesScanned,
            int              totalFindings,
            Map<String, Long> findingsBySeverity
    ) {}

    private record FindingDto(
            String      id,
            String      ruleId,
            String      ruleName,
            String      severity,
            String      confidence,
            String      cwe,
            String      owasp,
            LocationDto location,
            String      message,
            String      remediation,
            String      detectedAt
    ) {}

    private record LocationDto(
            String filePath,
            int    startLine,
            int    endLine,
            String snippet
    ) {}
}