package com.minisast.core.rules;

import com.minisast.core.rules.config.ConfigSecretRule;
import com.minisast.core.rules.java.CommandInjectionRule;
import com.minisast.core.rules.java.HardcodedSecretRule;
import com.minisast.core.rules.java.SqlInjectionRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public final class RuleRegistry {

    private static final Logger log = LoggerFactory.getLogger(RuleRegistry.class);

    private final List<Rule> rules;

    public RuleRegistry() {
        this.rules = List.of(
                new SqlInjectionRule(),
                new HardcodedSecretRule(),
                new CommandInjectionRule(),
                new ConfigSecretRule()      // ← added
        );
        log.info("Rule registry initialized with {} rules", rules.size());
        rules.forEach(r -> log.debug("  Loaded rule: {} [{}]", r.getId(), r.getSeverity()));
    }

    public List<Rule> all()     { return rules; }
    public List<Rule> enabled() { return rules.stream().filter(Rule::isEnabled).toList(); }

    public List<Rule> forLanguage(String language) {
        return rules.stream()
                .filter(Rule::isEnabled)
                .filter(r -> r.getLanguage().equals("*")
                        || r.getLanguage().equalsIgnoreCase(language))
                .toList();
    }

    public int size() { return rules.size(); }
}