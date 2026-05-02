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
 * Detects command injection vulnerabilities.
 *
 * Attack scenario:
 *   Runtime.getRuntime().exec("ping " + userInput);
 *   -> attacker passes: "; rm -rf /"
 *   -> executed as:     ping ; rm -rf /
 *
 * Detection strategy:
 *   Match MethodCallExpr where:
 *     1. Method is Runtime.exec()
 *     2. Argument contains dynamic string concatenation
 *   Also matches new ProcessBuilder() with dynamic arguments.
 *
 * CWE-78: Improper Neutralization of Special Elements used in an OS Command
 * OWASP A03:2021 - Injection
 */
public final class CommandInjectionRule extends JavaAstRule {

    private static final Set<String> EXEC_METHODS    = Set.of("exec");
    private static final Set<String> PROCESS_CLASSES = Set.of("ProcessBuilder", "Runtime");

    public CommandInjectionRule() {
        super(
                "JAVA-CMD-001",
                "Command Injection",
                "User-controlled data is concatenated into an OS command string. " +
                        "An attacker can inject arbitrary shell commands.",
                Severity.CRITICAL,
                Confidence.HIGH,
                "CWE-78",
                "A03:2021 - Injection",
                "Never pass user-controlled input to exec(). If OS commands are required, " +
                        "use an allowlist of permitted commands, pass arguments as separate array " +
                        "elements (not a single concatenated string), and run in a sandboxed environment."
        );
    }

    @Override
    public List<RuleMatch> analyze(CompilationUnit cu, String filePath) {
        List<RuleMatch> matches = new ArrayList<>();
        cu.accept(new CommandInjectionVisitor(filePath, matches), null);
        return matches;
    }

    private final class CommandInjectionVisitor extends VoidVisitorAdapter<Void> {

        private final String          filePath;
        private final List<RuleMatch> matches;

        CommandInjectionVisitor(String filePath, List<RuleMatch> matches) {
            this.filePath = filePath;
            this.matches  = matches;
        }

        @Override
        public void visit(MethodCallExpr call, Void arg) {
            super.visit(call, arg);

            if (!EXEC_METHODS.contains(call.getNameAsString())) return;

            boolean isRuntimeCall = call.getScope()
                    .map(scope -> scope.toString().contains("Runtime"))
                    .orElse(false);

            if (!isRuntimeCall) return;

            for (Expression argument : call.getArguments()) {
                if (containsDynamicConcatenation(argument)) {
                    int line = call.getBegin().map(p -> p.line).orElse(0);
                    matches.add(new RuleMatch(
                            getId(),
                            new Location(filePath, line, line, 0, 0,
                                    truncate(call.toString(), 120)),
                            "Runtime.exec() called with dynamic string concatenation. " +
                                    "If any concatenated value is user-controlled, arbitrary " +
                                    "OS commands can be executed.",
                            Confidence.HIGH
                    ));
                    return;
                }
            }
        }

        @Override
        public void visit(ObjectCreationExpr creation, Void arg) {
            super.visit(creation, arg);

            String typeName = creation.getType().getNameAsString();
            if (!PROCESS_CLASSES.contains(typeName)) return;

            for (Expression argument : creation.getArguments()) {
                if (isDynamic(argument) || containsDynamicConcatenation(argument)) {
                    int line = creation.getBegin().map(p -> p.line).orElse(0);
                    matches.add(new RuleMatch(
                            getId(),
                            new Location(filePath, line, line, 0, 0,
                                    truncate(creation.toString(), 120)),
                            "new ProcessBuilder() constructed with dynamic argument. " +
                                    "Verify no user-controlled data reaches this call.",
                            Confidence.MEDIUM
                    ));
                    return;
                }
            }
        }

        private boolean containsDynamicConcatenation(Expression expr) {
            if (expr instanceof BinaryExpr binary
                    && binary.getOperator() == BinaryExpr.Operator.PLUS) {
                if (isDynamic(binary.getLeft()) || isDynamic(binary.getRight())) return true;
                return containsDynamicConcatenation(binary.getLeft())
                        || containsDynamicConcatenation(binary.getRight());
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