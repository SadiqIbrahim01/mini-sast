package com.minisast.core.rules.java;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.minisast.core.model.Confidence;
import com.minisast.core.model.Location;
import com.minisast.core.model.Severity;
import com.minisast.core.rules.JavaAstRule;
import com.minisast.core.rules.RuleMatch;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Detects SQL injection vulnerabilities via AST analysis.
 *
 * Detection strategy (Phase 2 — direct concatenation):
 *   Match MethodCallExpr where:
 *     1. Method name is a known SQL execution method
 *     2. At least one argument contains a BinaryExpr with operator '+'
 *        that includes a non-literal operand (variable/method call)
 *
 * This catches the most common and most dangerous pattern:
 *   stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
 *
 * False positive risk: LOW
 *   A BinaryExpr '+' argument to a SQL method is almost always
 *   string concatenation of user data. We reduce FP further by
 *   requiring the '+' operand to be non-literal.
 *
 * What this does NOT catch (Phase 3 — taint analysis):
 *   String query = "SELECT ... WHERE id = " + userId;
 *   stmt.executeQuery(query);  <- variable alias, not caught here
 *
 * CWE-89: Improper Neutralization of Special Elements used in SQL Command
 * OWASP A03:2021 - Injection
 */
public final class SqlInjectionRule extends JavaAstRule {

    private static final Set<String> SQL_EXEC_METHODS = Set.of(
            "executeQuery",
            "executeUpdate",
            "execute",
            "executeBatch",
            "addBatch",
            "prepareStatement",
            "prepareCall",
            "nativeSQL"
    );

    public SqlInjectionRule() {
        super(
                "JAVA-SQL-001",
                "SQL Injection",
                "User-controlled data is concatenated directly into a SQL query string, " +
                        "allowing an attacker to alter query logic and access or modify arbitrary data.",
                Severity.CRITICAL,
                Confidence.HIGH,
                "CWE-89",
                "A03:2021 - Injection",
                "Use PreparedStatement with parameterized queries: " +
                        "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\"); " +
                        "ps.setInt(1, userId);"
        );
    }

    @Override
    public List<RuleMatch> analyze(CompilationUnit cu, String filePath) {
        List<RuleMatch> matches = new ArrayList<>();
        cu.accept(new SqlInjectionVisitor(filePath, matches), null);
        return matches;
    }

    private final class SqlInjectionVisitor extends VoidVisitorAdapter<Void> {

        private final String          filePath;
        private final List<RuleMatch> matches;

        SqlInjectionVisitor(String filePath, List<RuleMatch> matches) {
            this.filePath = filePath;
            this.matches  = matches;
        }

        @Override
        public void visit(MethodCallExpr methodCall, Void arg) {
            super.visit(methodCall, arg);

            String methodName = methodCall.getNameAsString();

            if (!SQL_EXEC_METHODS.contains(methodName)) {
                return;
            }

            for (Expression argument : methodCall.getArguments()) {
                if (containsDynamicConcatenation(argument)) {
                    int    line    = methodCall.getBegin()
                            .map(p -> p.line)
                            .orElse(0);
                    String snippet = methodCall.toString();

                    Location location = new Location(
                            filePath, line, line, 0, 0, truncate(snippet, 120)
                    );

                    matches.add(new RuleMatch(
                            getId(),
                            location,
                            "SQL method '%s()' called with dynamic string concatenation. "
                                    .formatted(methodName) +
                                    "If any concatenated value is user-controlled, this is exploitable.",
                            Confidence.HIGH
                    ));

                    return;
                }
            }
        }

        private boolean containsDynamicConcatenation(Expression expr) {
            if (expr instanceof BinaryExpr binary) {
                if (binary.getOperator() == BinaryExpr.Operator.PLUS) {
                    Expression left  = binary.getLeft();
                    Expression right = binary.getRight();

                    if (isDynamic(left) || isDynamic(right)) {
                        return true;
                    }

                    return containsDynamicConcatenation(left)
                            || containsDynamicConcatenation(right);
                }
            }
            return false;
        }

        private boolean isDynamic(Expression expr) {
            return !(expr instanceof StringLiteralExpr)
                    && !(expr instanceof CharLiteralExpr)
                    && !(expr instanceof IntegerLiteralExpr)
                    && !(expr instanceof LongLiteralExpr)
                    && !(expr instanceof DoubleLiteralExpr)
                    && !(expr instanceof BooleanLiteralExpr)
                    && !(expr instanceof NullLiteralExpr);
        }

        private String truncate(String s, int max) {
            return s.length() <= max ? s : s.substring(0, max) + "...";
        }
    }
}