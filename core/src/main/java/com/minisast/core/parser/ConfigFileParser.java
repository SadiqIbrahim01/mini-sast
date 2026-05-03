package com.minisast.core.parser;

import com.minisast.core.exception.ParseException;
import com.minisast.core.model.Language;
import com.minisast.core.rules.Rule;
import com.minisast.core.rules.RuleMatch;
import com.minisast.core.rules.config.ConfigSecretRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses configuration files line by line and runs config-specific rules.
 *
 * Unlike JavaLanguageParser which builds an AST, this parser works at the
 * line level. Config files have no grammar that benefits from tree parsing —
 * each line is independently meaningful.
 *
 * IMPORTANT DESIGN DECISION — why line-by-line and not a YAML/properties parser:
 *
 * 1. Universal format support: one parser handles .env, .yml, .properties,
 *    .toml, .ini, .conf without pulling in format-specific libraries.
 *
 * 2. Robustness: real config files in the wild are often malformed.
 *    A strict YAML parser would throw on the first syntax error and miss
 *    everything else. Line-by-line is tolerant by nature.
 *
 * 3. The rule logic (ConfigSecretRule.parseLine) handles format differences
 *    — KEY=VALUE vs KEY: VALUE — at the rule level, not the parser level.
 *    This keeps concerns separated: the parser handles I/O and file access,
 *    the rule handles format parsing and detection.
 *
 * Security: reads files as UTF-8, limits processing to files already
 * size-checked by FileWalker (10MB max).
 */
public final class ConfigFileParser implements LanguageParser {

    private static final Logger log = LoggerFactory.getLogger(ConfigFileParser.class);

    @Override
    public Language getLanguage() {
        return Language.CONFIG;
    }

    @Override
    public boolean supports(Path file) {
        // Delegates language detection to Language enum
        return Language.fromPath(file)
                .map(lang -> lang == Language.CONFIG)
                .orElse(false);
    }

    @Override
    public List<RuleMatch> analyze(Path file, List<Rule> rules) throws ParseException {
        log.debug("Config scan: {}", file.getFileName());

        // Extract only ConfigSecretRule instances
        List<ConfigSecretRule> configRules = rules.stream()
                .filter(ConfigSecretRule.class::isInstance)
                .map(ConfigSecretRule.class::cast)
                .toList();

        if (configRules.isEmpty()) {
            log.debug("No config rules applicable for: {}", file.getFileName());
            return List.of();
        }

        List<String> lines = readLines(file);
        String filePath  = file.toAbsolutePath().toString();
        String fileName  = file.getFileName().toString();

        List<RuleMatch> matches = new ArrayList<>();

        for (int i = 0; i < lines.size(); i++) {
            int lineNum = i + 1; // 1-based
            String line = lines.get(i);

            for (ConfigSecretRule rule : configRules) {
                try {
                    rule.analyzeLine(line, lineNum, filePath, fileName)
                            .ifPresent(matches::add);
                } catch (Exception e) {
                    log.warn("ConfigSecretRule error on {}:{} — {}",
                            file.getFileName(), lineNum, e.getMessage());
                }
            }
        }

        log.debug("Config scan complete: {} — {} match(es)", file.getFileName(), matches.size());
        return matches;
    }

    private List<String> readLines(Path file) throws ParseException {
        try {
            return Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new ParseException(
                    file.toString(),
                    "Cannot read config file: " + e.getMessage(), e
            );
        }
    }
}