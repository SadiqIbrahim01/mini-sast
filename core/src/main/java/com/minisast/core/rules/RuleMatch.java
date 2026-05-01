package com.minisast.core.rules;

import com.minisast.core.model.Confidence;
import com.minisast.core.model.Location;

/**
 * What a Rule returns when it detects a pattern.
 *
 * Deliberately separate from Finding:
 *   - RuleMatch is raw engine output (ruleId + location + message)
 *   - Finding is the enriched, reportable object (adds metadata from Rule definition)
 *
 * ScanEngine converts RuleMatch → Finding by merging in rule metadata.
 * This separation means rules stay simple — they don't need to know about
 * CWE, OWASP, remediation text, etc. That lives in rule configuration.
 */
public record RuleMatch(
        String     ruleId,
        Location   location,
        String     message,
        Confidence confidence
) {
    public RuleMatch {
        if (ruleId == null || ruleId.isBlank())
            throw new IllegalArgumentException("ruleId is required");
        if (location == null)
            throw new IllegalArgumentException("location is required");
        if (confidence == null)
            confidence = Confidence.MEDIUM;
        if (message == null)
            message = "";
    }
}