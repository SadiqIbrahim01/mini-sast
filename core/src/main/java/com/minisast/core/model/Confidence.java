package com.minisast.core.model;

/**
 * How confident the rule engine is in a finding.
 *
 * This is distinct from Severity on purpose:
 *   - Severity:   how bad is the vulnerability if real?
 *   - Confidence: how sure are we that it actually IS a vulnerability?
 *
 * A HIGH severity / LOW confidence finding (e.g. a possible SQL injection
 * that might be safely parameterized elsewhere) should be triaged differently
 * than a HIGH severity / HIGH confidence finding.
 *
 * This field exists to reduce alert fatigue — developers stop reading
 * reports that cry wolf on every finding.
 */
public enum Confidence {
    HIGH  ("HIGH",   "Near-certain finding, minimal expected false positives"),
    MEDIUM("MEDIUM", "Likely finding, some manual review advised"),
    LOW   ("LOW",    "Possible finding, manual verification required");

    private final String label;
    private final String description;

    Confidence(String label, String description) {
        this.label = label;
        this.description = description;
    }

    public String getLabel()       { return label; }
    public String getDescription() { return description; }
}