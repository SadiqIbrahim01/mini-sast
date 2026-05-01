package com.minisast.core.engine;

import com.minisast.core.model.Severity;

/**
 * Immutable configuration for a single scan run.
 * Built via the nested Builder — callers use named setters, not argument lists.
 */
public record ScanConfiguration(
        Severity minimumSeverity,
        boolean  failOnParseError,
        int      maxFileSizeMb
) {

    public static ScanConfiguration defaults() {
        return new Builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Severity minimumSeverity = Severity.LOW;
        private boolean  failOnParseError = false;
        private int      maxFileSizeMb   = 10;

        public Builder minimumSeverity(Severity v) { this.minimumSeverity = v; return this; }
        public Builder failOnParseError(boolean v) { this.failOnParseError = v; return this; }
        public Builder maxFileSizeMb(int v)        { this.maxFileSizeMb   = v; return this; }

        public ScanConfiguration build() {
            return new ScanConfiguration(minimumSeverity, failOnParseError, maxFileSizeMb);
        }
    }
}