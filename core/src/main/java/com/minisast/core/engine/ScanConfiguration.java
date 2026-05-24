package com.minisast.core.engine;

import com.minisast.core.model.Severity;

import java.util.Set;

/**
 * Immutable configuration for a single scan run.
 *
 * disabledRules: rule IDs explicitly turned off for this scan.
 * Applied before rule dispatch — disabled rules produce no matches
 * and consume no CPU time.
 */
public record ScanConfiguration(
        Severity    minimumSeverity,
        boolean     failOnParseError,
        int         maxFileSizeMb,
        Set<String> disabledRules      // rule IDs to skip entirely
) {

    public ScanConfiguration {
        // Defensive copy — caller cannot mutate the set after construction
        disabledRules = disabledRules != null ? Set.copyOf(disabledRules) : Set.of();
    }

    public static ScanConfiguration defaults() {
        return new Builder().build();
    }

    public boolean isRuleDisabled(String ruleId) {
        return disabledRules.contains(ruleId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Severity    minimumSeverity = Severity.LOW;
        private boolean     failOnParseError = false;
        private int         maxFileSizeMb   = 10;
        private Set<String> disabledRules   = Set.of();

        public Builder minimumSeverity(Severity v) { this.minimumSeverity = v; return this; }
        public Builder failOnParseError(boolean v) { this.failOnParseError = v; return this; }
        public Builder maxFileSizeMb(int v)        { this.maxFileSizeMb   = v; return this; }
        public Builder disabledRules(Set<String> v){ this.disabledRules   = v; return this; }

        public ScanConfiguration build() {
            return new ScanConfiguration(
                    minimumSeverity, failOnParseError, maxFileSizeMb, disabledRules
            );
        }
    }
}