package com.minisast.core.parser;

import com.minisast.core.exception.ParseException;
import com.minisast.core.model.Language;
import com.minisast.core.rules.Rule;
import com.minisast.core.rules.RuleMatch;

import java.nio.file.Path;
import java.util.List;

/**
 * Contract for language-specific parsers.
 *
 * Architecture decision: one parser per language.
 * Each parser knows how to:
 *   1. Determine if it handles a given file (supports)
 *   2. Parse the file into an AST (internal)
 *   3. Run applicable rules against that AST (analyze)
 *
 * Phase 2 will implement JavaLanguageParser.
 * Phase 3+ can add PythonLanguageParser, etc. — zero engine changes required.
 *
 * ParseException is checked here because callers MUST handle parse failures
 * (log + skip vs. abort) — it's a recoverable failure, not a bug.
 */
public interface LanguageParser {
    Language getLanguage();
    boolean  supports(Path file);
    List<RuleMatch> analyze(Path file, List<Rule> rules) throws ParseException;
}