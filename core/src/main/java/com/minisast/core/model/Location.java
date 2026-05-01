package com.minisast.core.model;

/**
 * Precise location of a finding in source code.
 *
 * Using a Java record: immutable, no boilerplate, auto equals/hashCode/toString.
 * Compact constructor validates invariants before the object exists.
 *
 * Column positions are 0-based (IDE convention).
 * Line positions are 1-based (human convention, matches IDE gutter numbers).
 */
public record Location(
        String filePath,
        int    startLine,
        int    endLine,
        int    startColumn,
        int    endColumn,
        String snippet        // the actual code fragment for context
) {

    /** Compact constructor — validates all fields before object is created */
    public Location {
        if (filePath == null || filePath.isBlank()) {
            throw new IllegalArgumentException("filePath must not be null or blank");
        }
        if (startLine < 1) {
            throw new IllegalArgumentException(
                    "startLine must be >= 1 (1-based), got: " + startLine);
        }
        if (endLine < startLine) {
            throw new IllegalArgumentException(
                    "endLine (%d) must be >= startLine (%d)".formatted(endLine, startLine));
        }
        if (startColumn < 0 || endColumn < 0) {
            throw new IllegalArgumentException("Column positions must be >= 0");
        }
        snippet = snippet == null ? "" : snippet;
    }

    /** Quick factory for single-line, no-snippet locations */
    public static Location of(String filePath, int line) {
        return new Location(filePath, line, line, 0, 0, "");
    }

    /** Factory with snippet for richer output */
    public static Location of(String filePath, int startLine, int endLine, String snippet) {
        return new Location(filePath, startLine, endLine, 0, 0, snippet);
    }

    /** Returns "file.java:42" format — compatible with IDE hyperlinks */
    @Override
    public String toString() {
        return "%s:%d".formatted(filePath, startLine);
    }
}