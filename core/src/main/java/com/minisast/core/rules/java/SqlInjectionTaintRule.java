package com.minisast.core.rules.java;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.minisast.core.model.Confidence;
import com.minisast.core.model.Severity;
import com.minisast.core.rules.JavaAstRule;
import com.minisast.core.rules.RuleMatch;
import com.minisast.core.taint.TaintAnalyzer;
import com.minisast.core.taint.TaintFlow;

import java.util.ArrayList;
import java.util.List;

/**
 * Detects SQL injection via intra-procedural taint analysis.
 *
 * COMPLEMENTS SqlInjectionRule (JAVA-SQL-001):
 *   JAVA-SQL-001: Catches direct concatenation at the sink call
 *     stmt.executeQuery("SELECT..." + userId)
 *
 *   JAVA-SQL-002 (this rule): Catches aliased concatenation and source tracking
 *     String query = "SELECT..." + userId;
 *     stmt.executeQuery(query);             ← alias, JAVA-SQL-001 misses this
 *
 *     String userId = request.getParameter("id");  ← HTTP source tracked
 *     String query  = "SELECT..." + userId;
 *     stmt.executeQuery(query);                     ← full flow with context
 *
 * Both rules can fire on the same method when patterns overlap.
 * Each provides distinct, complementary diagnostic information.
 *
 * The TaintAnalyzer is stateless and shared — no concurrency issues.
 */
public final class SqlInjectionTaintRule extends JavaAstRule {

    private static final TaintAnalyzer ANALYZER = new TaintAnalyzer();

    public SqlInjectionTaintRule() {
        super(
                "JAVA-SQL-002",
                "SQL Injection via Taint Flow",
                "User-controlled or dynamically-constructed data flows into a SQL execution " +
                        "method through variable assignments. The injection point is not inline at the " +
                        "sink call but reaches it via tainted variable aliasing.",
                Severity.CRITICAL,
                Confidence.HIGH,
                "CWE-89",
                "A03:2021 - Injection",
                "Use PreparedStatement with parameterized queries. Ensure all user input is " +
                        "bound as parameters, never concatenated into SQL strings at any point in " +
                        "the data flow — including intermediate variable assignments."
        );
    }

    @Override
    public List<RuleMatch> analyze(CompilationUnit cu, String filePath) {
        List<RuleMatch> matches = new ArrayList<>();

        // Analyse every method in the compilation unit independently
        cu.findAll(MethodDeclaration.class).forEach(method -> {
            List<TaintFlow> flows = ANALYZER.analyze(method, filePath);

            flows.stream()
                    .map(flow -> new RuleMatch(
                            getId(),
                            flow.sinkLocation(),
                            flow.flowDescription(),
                            Confidence.HIGH
                    ))
                    .forEach(matches::add);
        });

        return matches;
    }
}