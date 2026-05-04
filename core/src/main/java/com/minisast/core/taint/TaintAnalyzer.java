package com.minisast.core.taint;

import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;
import com.minisast.core.model.Location;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Intra-procedural taint analysis engine.
 *
 * "Intra-procedural" means we analyse one method at a time, sequentially
 * through its statements. We do not follow calls into other methods
 * (that is inter-procedural analysis — Phase 3 extension or beyond).
 *
 * Algorithm:
 *   For each method body, iterate statements in order, maintaining a
 *   taintedVars map (variable name → TaintedVariable). For each statement:
 *
 *   1. SOURCE CHECK: does this statement assign a variable from a known
 *      user-input source (request.getParameter, etc.)?
 *      → add to taintedVars with source type HTTP_PARAMETER etc.
 *
 *   2. PROPAGATION CHECK: does this statement assign a variable from an
 *      expression that is dynamically constructed (BinaryExpr with non-literal)
 *      or contains a reference to an already-tainted variable?
 *      → add to taintedVars, preserving original source type
 *
 *   3. SINK CHECK: does this statement call a known SQL method where any
 *      argument is tainted or contains a tainted variable?
 *      → produce a TaintFlow
 *
 * Order is critical: we check sources/propagation before sinks so a
 * single statement that both assigns and uses (rare) is handled correctly.
 *
 * Thread safety: TaintAnalyzer is stateless. One instance can analyze
 * multiple methods concurrently with no shared mutable state.
 */
public final class TaintAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(TaintAnalyzer.class);

    // ── Known HTTP taint sources ──────────────────────────────────────────────
    // Method name → TaintSource type
    // These are the most common HttpServletRequest methods that expose user input
    private static final Map<String, TaintSource> HTTP_SOURCES = Map.of(
            "getParameter",       TaintSource.HTTP_PARAMETER,
            "getParameterValues", TaintSource.HTTP_PARAMETER,
            "getQueryString",     TaintSource.HTTP_PARAMETER,
            "getPathInfo",        TaintSource.HTTP_PARAMETER,
            "getRequestURI",      TaintSource.HTTP_PARAMETER,
            "getHeader",          TaintSource.HTTP_HEADER,
            "getHeaders",         TaintSource.HTTP_HEADER,
            "getCookies",         TaintSource.HTTP_COOKIE,
            "getReader",          TaintSource.HTTP_BODY,
            "getInputStream",     TaintSource.HTTP_BODY
    );

    // ── SQL sink methods ──────────────────────────────────────────────────────
    private static final Set<String> SQL_SINKS = Set.of(
            "executeQuery",
            "executeUpdate",
            "execute",
            "executeBatch",
            "addBatch",
            "prepareStatement",
            "prepareCall",
            "nativeSQL"
    );

    /**
     * Analyse a single method for taint flows.
     *
     * @param method   The method declaration to analyse
     * @param filePath Absolute path to the source file (for Location)
     * @return         All taint flows found; empty if none
     */
    public List<TaintFlow> analyze(MethodDeclaration method, String filePath) {
        // LinkedHashMap preserves insertion order — useful for debugging flow paths
        Map<String, TaintedVariable> taintedVars = new LinkedHashMap<>();
        List<TaintFlow>              flows        = new ArrayList<>();

        method.getBody().ifPresent(body -> {
            for (Statement stmt : body.getStatements()) {
                // Order matters: check sources then propagation then sinks
                // Source → Propagation → Sink within each statement
                processStatement(stmt, taintedVars, flows, filePath);
            }
        });

        if (!flows.isEmpty()) {
            log.debug("Method '{}': {} taint flow(s) found",
                    method.getNameAsString(), flows.size());
        }

        return flows;
    }

    // ── Statement processing ──────────────────────────────────────────────────

    private void processStatement(
            Statement stmt,
            Map<String, TaintedVariable> taintedVars,
            List<TaintFlow> flows,
            String filePath
    ) {
        if (!(stmt instanceof ExpressionStmt exprStmt)) return;

        Expression expr = exprStmt.getExpression();

        // Variable declaration: String query = "SELECT..." + userId;
        if (expr instanceof VariableDeclarationExpr varDecl) {
            for (VariableDeclarator var : varDecl.getVariables()) {
                var.getInitializer().ifPresent(init -> {
                    int line = var.getBegin().map(p -> p.line).orElse(0);
                    checkAndTrackTaint(var.getNameAsString(), init, line, taintedVars);
                });
            }
        }

        // Assignment: query = "SELECT..." + userId;
        if (expr instanceof AssignExpr assign) {
            String target = extractTargetName(assign.getTarget());
            if (target != null) {
                int line = assign.getBegin().map(p -> p.line).orElse(0);
                checkAndTrackTaint(target, assign.getValue(), line, taintedVars);
            }
        }

        // Method call — could be a sink
        if (expr instanceof MethodCallExpr call) {
            checkSinkCall(call, taintedVars, filePath, flows);
        }
    }

    // ── Taint tracking ────────────────────────────────────────────────────────

    /**
     * Determines if an assignment introduces or propagates taint.
     * If it does, records the tainted variable.
     */
    private void checkAndTrackTaint(
            String varName,
            Expression init,
            int line,
            Map<String, TaintedVariable> taintedVars
    ) {
        // Priority 1: direct HTTP source (request.getParameter etc.)
        Optional<TaintSource> httpSource = detectHttpSource(init);
        if (httpSource.isPresent()) {
            TaintedVariable tv = new TaintedVariable(varName, httpSource.get(), line);
            taintedVars.put(varName, tv);
            log.debug("Taint source at line {}: {} ({})", line, varName, httpSource.get());
            return;
        }

        // Priority 2: expression contains a tainted variable (propagation)
        if (containsTaintedVariable(init, taintedVars)) {
            // Preserve the original source type so the report says
            // "HTTP parameter flows into executeQuery" not just "taint propagated"
            TaintSource propagatedSource = findOriginatingTaint(init, taintedVars)
                    .map(TaintedVariable::source)
                    .orElse(TaintSource.TAINT_PROPAGATED);

            TaintedVariable tv = new TaintedVariable(varName, propagatedSource, line);
            taintedVars.put(varName, tv);
            log.debug("Taint propagated at line {}: {} <- {}", line, varName, propagatedSource);
            return;
        }

        // Priority 3: dynamic string concatenation (even without known HTTP source)
        // This catches: String query = "SELECT..." + someParam;
        // where someParam came from a method parameter (not HTTP — still dangerous at SQL sink)
        if (isDynamicConcat(init)) {
            TaintedVariable tv = new TaintedVariable(varName, TaintSource.DYNAMIC_CONCAT, line);
            taintedVars.put(varName, tv);
            log.debug("Dynamic concat taint at line {}: {}", line, varName);
        }
    }

    // ── Sink detection ────────────────────────────────────────────────────────

    /**
     * Checks if a method call is a SQL sink receiving tainted data.
     * Produces at most one TaintFlow per sink call (first tainted argument wins).
     */
    private void checkSinkCall(
            MethodCallExpr call,
            Map<String, TaintedVariable> taintedVars,
            String filePath,
            List<TaintFlow> flows
    ) {
        if (!SQL_SINKS.contains(call.getNameAsString())) return;
        if (taintedVars.isEmpty()) return;

        for (Expression arg : call.getArguments()) {

            // Case 1: argument IS a tainted variable directly
            //   stmt.executeQuery(query)  ← query is in taintedVars
            if (arg instanceof NameExpr name) {
                TaintedVariable tainted = taintedVars.get(name.getNameAsString());
                if (tainted != null) {
                    flows.add(buildTaintFlow(tainted, tainted, call, filePath));
                    return;
                }
            }

            // Case 2: argument contains a tainted variable in a concatenation
            //   stmt.executeQuery("SELECT..." + taintedVar + "...")
            if (containsTaintedVariable(arg, taintedVars)) {
                findOriginatingTaint(arg, taintedVars).ifPresent(origin -> {
                    // The "sink variable" here is the tainted var within the expression
                    flows.add(buildTaintFlow(origin, origin, call, filePath));
                });
                return;
            }
        }
    }

    private TaintFlow buildTaintFlow(
            TaintedVariable origin,
            TaintedVariable atSink,
            MethodCallExpr call,
            String filePath
    ) {
        int    sinkLine = call.getBegin().map(p -> p.line).orElse(0);
        String snippet  = truncate(call.toString(), 120);

        Location sinkLocation = new Location(filePath, sinkLine, sinkLine, 0, 0, snippet);

        String description = buildFlowDescription(origin, atSink, call.getNameAsString());

        return new TaintFlow(origin, atSink, call.getNameAsString(), sinkLocation, description);
    }

    private String buildFlowDescription(
            TaintedVariable origin,
            TaintedVariable atSink,
            String sinkMethod
    ) {
        return switch (origin.source()) {
            case HTTP_PARAMETER ->
                    "HTTP request parameter assigned to '%s' at line %d flows into %s() — "
                            .formatted(origin.name(), origin.sourceLine(), sinkMethod) +
                            "if the parameter value is attacker-controlled, this is exploitable.";
            case HTTP_HEADER ->
                    "HTTP request header assigned to '%s' at line %d flows into %s() — "
                            .formatted(origin.name(), origin.sourceLine(), sinkMethod) +
                            "headers can be set by a client and must not reach SQL sinks.";
            case HTTP_COOKIE ->
                    "HTTP cookie value assigned to '%s' at line %d flows into %s()."
                            .formatted(origin.name(), origin.sourceLine(), sinkMethod);
            case HTTP_BODY ->
                    "HTTP request body assigned to '%s' at line %d flows into %s()."
                            .formatted(origin.name(), origin.sourceLine(), sinkMethod);
            case DYNAMIC_CONCAT ->
                    "Dynamically constructed string '%s' (line %d) passed to %s() — "
                            .formatted(atSink.name(), origin.sourceLine(), sinkMethod) +
                            "concatenated variables may contain user-controlled data.";
            case TAINT_PROPAGATED ->
                    "Variable '%s' (line %d) derived from tainted data flows into %s()."
                            .formatted(atSink.name(), origin.sourceLine(), sinkMethod);
        };
    }

    // ── Expression helpers ────────────────────────────────────────────────────

    /**
     * Returns the TaintSource if the expression is a call to a known HTTP source method.
     * Does NOT require the scope to be "request" — we match on method name only.
     * Rationale: users may use different variable names (req, httpRequest, servletRequest).
     */
    private Optional<TaintSource> detectHttpSource(Expression expr) {
        if (expr instanceof MethodCallExpr call) {
            return Optional.ofNullable(HTTP_SOURCES.get(call.getNameAsString()));
        }
        return Optional.empty();
    }

    /**
     * Returns true if the expression contains a reference to any tainted variable.
     * Recurses into BinaryExpr, EnclosedExpr, and method call arguments.
     */
    private boolean containsTaintedVariable(
            Expression expr,
            Map<String, TaintedVariable> taintedVars
    ) {
        if (expr instanceof NameExpr name) {
            return taintedVars.containsKey(name.getNameAsString());
        }
        if (expr instanceof BinaryExpr binary) {
            return containsTaintedVariable(binary.getLeft(), taintedVars)
                    || containsTaintedVariable(binary.getRight(), taintedVars);
        }
        if (expr instanceof EnclosedExpr enclosed) {
            return containsTaintedVariable(enclosed.getInner(), taintedVars);
        }
        if (expr instanceof MethodCallExpr call) {
            // Check if tainted vars appear in method arguments
            // e.g. String q = escape(taintedVar) — still propagates taint
            return call.getArguments().stream()
                    .anyMatch(arg -> containsTaintedVariable(arg, taintedVars));
        }
        return false;
    }

    /**
     * Finds the first tainted variable referenced within an expression.
     * Used to attribute the finding to the correct source variable.
     */
    private Optional<TaintedVariable> findOriginatingTaint(
            Expression expr,
            Map<String, TaintedVariable> taintedVars
    ) {
        if (expr instanceof NameExpr name) {
            return Optional.ofNullable(taintedVars.get(name.getNameAsString()));
        }
        if (expr instanceof BinaryExpr binary) {
            Optional<TaintedVariable> left = findOriginatingTaint(binary.getLeft(), taintedVars);
            if (left.isPresent()) return left;
            return findOriginatingTaint(binary.getRight(), taintedVars);
        }
        if (expr instanceof EnclosedExpr enclosed) {
            return findOriginatingTaint(enclosed.getInner(), taintedVars);
        }
        return Optional.empty();
    }

    /**
     * Returns true if the expression is a BinaryExpr(+) that includes
     * at least one non-literal operand at any nesting depth.
     *
     * This detects dynamic string construction regardless of whether the
     * non-literal part is already in taintedVars:
     *   "SELECT * FROM " + tableName   → true  (tableName is non-literal)
     *   "SELECT * FROM " + "users"     → false (both literals)
     *   "SELECT " + col + " FROM " + t → true  (col and t are non-literals)
     */
    private boolean isDynamicConcat(Expression expr) {
        if (expr instanceof BinaryExpr binary
                && binary.getOperator() == BinaryExpr.Operator.PLUS) {
            return isNonLiteral(binary.getLeft())
                    || isNonLiteral(binary.getRight())
                    || isDynamicConcat(binary.getLeft())
                    || isDynamicConcat(binary.getRight());
        }
        return false;
    }

    private boolean isNonLiteral(Expression expr) {
        return !(expr instanceof StringLiteralExpr)
                && !(expr instanceof IntegerLiteralExpr)
                && !(expr instanceof LongLiteralExpr)
                && !(expr instanceof DoubleLiteralExpr)
                && !(expr instanceof BooleanLiteralExpr)
                && !(expr instanceof CharLiteralExpr)
                && !(expr instanceof NullLiteralExpr);
    }

    private String extractTargetName(Expression target) {
        if (target instanceof NameExpr n)        return n.getNameAsString();
        if (target instanceof FieldAccessExpr f) return f.getNameAsString();
        return null;
    }

    private String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}