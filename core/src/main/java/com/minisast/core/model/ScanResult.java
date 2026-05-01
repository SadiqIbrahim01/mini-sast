package com.minisast.core.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * The complete output of a scan operation.
 *
 * Design decisions:
 *  - findings is defensively copied → callers cannot mutate the result after creation
 *  - stats are computed here from findings → single source of truth
 *  - engineVersion is embedded → reports are self-contained, reproducible
 *  - scanId (UUID) → findings can be correlated across systems/databases later
 */
public record ScanResult(
        String    scanId,
        String    targetPath,
        Instant   scanTimestamp,
        long      durationMs,
        String    engineVersion,
        List<Finding>  findings,
        ScanStats stats
) {

    public ScanResult {
        findings = List.copyOf(findings); // immutable defensive copy
    }

    /**
     * Primary factory — computes stats automatically from findings.
     */
    public static ScanResult of(
            String        targetPath,
            long          durationMs,
            String        engineVersion,
            List<Finding> findings,
            int           filesScanned,
            long          linesScanned
    ) {
        Map<Severity, Long> bySeverity = findings.stream()
                .collect(Collectors.groupingBy(Finding::severity, Collectors.counting()));

        ScanStats stats = new ScanStats(
                filesScanned,
                linesScanned,
                findings.size(),
                bySeverity
        );

        return new ScanResult(
                UUID.randomUUID().toString(),
                targetPath,
                Instant.now(),
                durationMs,
                engineVersion,
                findings,
                stats
        );
    }

    public boolean hasFindings() {
        return !findings.isEmpty();
    }

    /** Filter findings at or above the given severity threshold */
    public List<Finding> findingsAtOrAbove(Severity minimumSeverity) {
        return findings.stream()
                .filter(f -> f.severity().isAtLeast(minimumSeverity))
                .toList();
    }
}