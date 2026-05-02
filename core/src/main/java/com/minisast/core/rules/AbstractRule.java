package com.minisast.core.rules;

import com.minisast.core.model.Confidence;
import com.minisast.core.model.Severity;

/**
 * Base class for all concrete rules.
 *
 * Handles the metadata contract from Rule interface.
 * Subclasses only implement detection logic — not boilerplate.
 *
 * All fields are final — rules are stateless value objects.
 * Immutability guarantees thread safety across concurrent scans.
 */
public abstract class AbstractRule implements Rule {

    private final String     id;
    private final String     name;
    private final String     description;
    private final Severity   severity;
    private final Confidence defaultConfidence;
    private final String     language;
    private final String     cwe;
    private final String     owasp;
    private final String     remediation;
    private final boolean    enabled;

    protected AbstractRule(
            String     id,
            String     name,
            String     description,
            Severity   severity,
            Confidence defaultConfidence,
            String     language,
            String     cwe,
            String     owasp,
            String     remediation
    ) {
        this.id               = id;
        this.name             = name;
        this.description      = description;
        this.severity         = severity;
        this.defaultConfidence = defaultConfidence;
        this.language         = language;
        this.cwe              = cwe;
        this.owasp            = owasp;
        this.remediation      = remediation;
        this.enabled          = true;
    }

    @Override public String     getId()               { return id; }
    @Override public String     getName()             { return name; }
    @Override public String     getDescription()      { return description; }
    @Override public Severity   getSeverity()         { return severity; }
    @Override public Confidence getDefaultConfidence(){ return defaultConfidence; }
    @Override public String     getLanguage()         { return language; }
    @Override public String     getCwe()              { return cwe; }
    @Override public String     getOwasp()            { return owasp; }
    @Override public String     getRemediation()      { return remediation; }
    @Override public boolean    isEnabled()           { return enabled; }
}