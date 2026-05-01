package com.minisast.core.model;

import java.time.Instant;
import java.util.UUID;

/**
 * A single security finding produced by the scan engine.
 *
 * Immutable by design:
 *   - Record fields are final
 *   - Builder pattern because we have 10+ fields (telescoping constructors are unreadable)
 *   - detectedAt set at build time, not passed in — callers can't fake timestamps
 *
 * CWE and OWASP fields are optional but important for professional reports.
 * A finding with CWE-89 means something specific to a security team.
 * A finding that just says "SQL injection" means much less.
 */
public record Finding(
        String     id,
        String     ruleId,
        String     ruleName,
        String     description,
        Severity   severity,
        Confidence confidence,
        Location   location,
        String     message,      // specific message for THIS finding instance
        String     remediation,  // how to fix it
        String     cwe,          // e.g. "CWE-89"
        String     owasp,        // e.g. "A03:2021 – Injection"
        Instant    detectedAt
) {

    /** Compact constructor validates required fields */
    public Finding {
        if (id == null || id.isBlank())         throw new IllegalArgumentException("id is required");
        if (ruleId == null || ruleId.isBlank()) throw new IllegalArgumentException("ruleId is required");
        if (severity == null)                   throw new IllegalArgumentException("severity is required");
        if (location == null)                   throw new IllegalArgumentException("location is required");
        if (confidence == null)                 confidence = Confidence.MEDIUM;
        if (detectedAt == null)                 detectedAt = Instant.now();
        cwe         = cwe         != null ? cwe         : "";
        owasp       = owasp       != null ? owasp       : "";
        remediation = remediation != null ? remediation : "";
        description = description != null ? description : "";
        message     = message     != null ? message     : "";
        ruleName    = ruleName    != null ? ruleName    : ruleId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String     id          = UUID.randomUUID().toString();
        private String     ruleId;
        private String     ruleName;
        private String     description;
        private Severity   severity;
        private Confidence confidence  = Confidence.MEDIUM;
        private Location   location;
        private String     message;
        private String     remediation;
        private String     cwe;
        private String     owasp;

        public Builder ruleId(String v)      { this.ruleId      = v; return this; }
        public Builder ruleName(String v)    { this.ruleName    = v; return this; }
        public Builder description(String v) { this.description = v; return this; }
        public Builder severity(Severity v)  { this.severity    = v; return this; }
        public Builder confidence(Confidence v){ this.confidence = v; return this; }
        public Builder location(Location v)  { this.location    = v; return this; }
        public Builder message(String v)     { this.message     = v; return this; }
        public Builder remediation(String v) { this.remediation = v; return this; }
        public Builder cwe(String v)         { this.cwe         = v; return this; }
        public Builder owasp(String v)       { this.owasp       = v; return this; }

        public Finding build() {
            return new Finding(
                    id, ruleId, ruleName, description,
                    severity, confidence, location,
                    message, remediation, cwe, owasp,
                    Instant.now()
            );
        }
    }
}