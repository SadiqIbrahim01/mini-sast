package com.minisast.core.taint;

/**
 * Tracks a single variable known to carry tainted data.
 *
 * Immutable — created once when taint is first detected, never mutated.
 * When taint propagates (A → B), B gets a new TaintedVariable record
 * preserving the original source type so reports can say:
 * "data from request.getParameter() flows into executeQuery()"
 * even when it travelled through several intermediate variables.
 */
public record TaintedVariable(
        String      name,        // variable name as it appears in source
        TaintSource source,      // how this variable became tainted
        int         sourceLine   // 1-based line where this variable was assigned
) {}