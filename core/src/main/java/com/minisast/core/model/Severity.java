package com.minisast.core.model;

/**
 * Severity levels for SAST findings.
 *
 * Design notes:
 * - Ordered by numeric level so isAtLeast() comparisons are O(1)
 * - ANSI codes kept here so any output layer (CLI, logs) can color correctly
 * - Aligns with industry standards: CVSS, OWASP Risk Rating
 */
public enum Severity {

    CRITICAL(5, "CRITICAL", "\u001B[31;1m"),  // Bright red  — exploit immediately
    HIGH    (4, "HIGH",     "\u001B[31m"),     // Red         — fix this sprint
    MEDIUM  (3, "MEDIUM",   "\u001B[33m"),     // Yellow      — fix soon
    LOW     (2, "LOW",      "\u001B[34m"),     // Blue        — track and fix
    INFO    (1, "INFO",     "\u001B[37m");     // White       — informational

    private static final String ANSI_RESET = "\u001B[0m";

    private final int level;
    private final String label;
    private final String ansiColor;

    Severity(int level, String label, String ansiColor) {
        this.level = level;
        this.label = label;
        this.ansiColor = ansiColor;
    }

    public int getLevel()      { return level; }
    public String getLabel()   { return label; }
    public String getAnsiColor() { return ansiColor; }

    /**
     * Returns true if this severity is equal to or worse than the threshold.
     * Use for filtering: show findings at or above a minimum severity.
     */
    public boolean isAtLeast(Severity threshold) {
        return this.level >= threshold.level;
    }

    public String colorize(String text) {
        return ansiColor + text + ANSI_RESET;
    }
}