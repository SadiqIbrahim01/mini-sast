package com.minisast.core.model;

import java.util.Map;

/**
 * Aggregated statistics for a completed scan.
 * Computed once at ScanResult creation — never mutated.
 */
public record ScanStats(
        int                  filesScanned,
        long                 linesScanned,
        int                  totalFindings,
        Map<Severity, Long>  findingsBySeverity
) {
    public ScanStats {
        findingsBySeverity = findingsBySeverity != null
                ? Map.copyOf(findingsBySeverity)
                : Map.of();
    }

    public static ScanStats empty() {
        return new ScanStats(0, 0L, 0, Map.of());
    }

    public long countBySeverity(Severity severity) {
        return findingsBySeverity.getOrDefault(severity, 0L);
    }
}