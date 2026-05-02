package com.minisast.core.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.minisast.core.model.Confidence;
import com.minisast.core.model.Severity;

import java.util.List;

/**
 * Extension of AbstractRule for Java AST-based rules.
 *
 * Receives the fully parsed CompilationUnit (the AST root).
 * Returns zero or more RuleMatches.
 *
 * Design note: we pass the filePath separately because the AST
 * does not always contain the absolute path — it depends on how
 * JavaParser was invoked. Keeping filePath explicit prevents
 * location bugs in reports.
 */
public abstract class JavaAstRule extends AbstractRule {

    protected JavaAstRule(
            String     id,
            String     name,
            String     description,
            Severity   severity,
            Confidence defaultConfidence,
            String     cwe,
            String     owasp,
            String     remediation
    ) {
        super(id, name, description, severity, defaultConfidence,
                "java", cwe, owasp, remediation);
    }

    /**
     * Analyse the AST and return all findings for this rule.
     *
     * @param cu       Parsed CompilationUnit (AST root)
     * @param filePath Absolute path to the source file (for Location)
     * @return         List of matches; empty if none found
     */
    public abstract List<RuleMatch> analyze(CompilationUnit cu, String filePath);
}