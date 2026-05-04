package com.minisast.core.taint;

import com.minisast.core.model.Location;

/**
 * A confirmed taint flow: from a taint source to a dangerous sink.
 *
 * Produced by TaintAnalyzer, consumed by SqlInjectionTaintRule
 * to create RuleMatch instances.
 *
 * Separating TaintFlow from RuleMatch keeps the taint analysis
 * independent of the rules framework — the same analyzer could
 * power command injection or path traversal rules in future phases.
 */
public record TaintFlow(
        TaintedVariable originVariable,  // where taint first entered
        TaintedVariable sinkVariable,    // the variable at the sink call
        String          sinkMethod,      // e.g. "executeQuery"
        Location        sinkLocation,    // precise location of the sink call
        String          flowDescription  // human-readable flow explanation
) {}