package com.minisast.core.rules;

import com.minisast.core.model.Confidence;
import com.minisast.core.model.Severity;

/**
 * Contract for all security rules.
 *
 * Rules are intentionally stateless — they receive data, return matches.
 * No instance state = thread safe by design.
 *
 * The getLanguage() method uses "*" for universal rules (e.g., hardcoded secrets
 * detection can apply to any file type). Language-specific rules return "java",
 * "python", etc. The engine uses this to filter which rules run per file.
 */
public interface Rule {
    String     getId();
    String     getName();
    String     getDescription();
    Severity   getSeverity();
    Confidence getDefaultConfidence();
    String     getLanguage();    // "java" | "python" | "*" (any)
    String     getCwe();         // e.g. "CWE-89"
    String     getOwasp();       // e.g. "A03:2021"
    String     getRemediation(); // human-readable fix guidance
    boolean    isEnabled();
}