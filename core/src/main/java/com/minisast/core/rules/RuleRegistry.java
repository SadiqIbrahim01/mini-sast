package com.minisast.core.rules;

import com.minisast.core.rules.java.CommandInjectionRule;
import com.minisast.core.rules.java.HardcodedSecretRule;
import com.minisast.core.rules.java.SqlInjectionRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Single source of truth for all built-in rules.
 *
 * Phase 2: rules are registered programmatically.
 * Phase 5: rules will also be loaded from YAML files (user-defined rules).
 *
 * The registry is immutable after construction — rules cannot be
 * added or removed at runtime. This prevents rules from being
 * disabled via API calls in a multi-tenant deployment (Phase 7).
 */
public final class RuleRegistry {

    private static final Logger log = LoggerFactory.getLogger(RuleRegistry.class);

    private final List<Rule> rules;

    /**
     * Constructs registry with all built-in rules.
     * Rule order determines execution order — put fastest rules first.
     */
    public RuleRegistry() {
        this.rules = List.of(
                new SqlInjectionRule(),
                new HardcodedSecretRule(),
                new CommandInjectionRule()
        );
        log.info("Rule registry initialized with {} rules", rules.size());
        rules.forEach(r -> log.debug("  Loaded rule: {} [{}]", r.getId(), r.getSeverity()));
    }

    /** Returns all rules (enabled and disabled) */
    public List<Rule> all() {
        return rules;
    }

    /** Returns only enabled rules */
    public List<Rule> enabled() {
        return rules.stream().filter(Rule::isEnabled).toList();
    }

    /** Returns enabled rules for a specific language (or universal rules) */
    public List<Rule> forLanguage(String language) {
        return rules.stream()
                .filter(Rule::isEnabled)
                .filter(r -> r.getLanguage().equals("*")
                        || r.getLanguage().equalsIgnoreCase(language))
                .toList();
    }

    public int size() {
        return rules.size();
    }
}