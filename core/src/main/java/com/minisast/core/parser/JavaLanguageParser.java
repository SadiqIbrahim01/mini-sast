package com.minisast.core.parser;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.minisast.core.exception.ParseException;
import com.minisast.core.model.Language;
import com.minisast.core.rules.JavaAstRule;
import com.minisast.core.rules.Rule;
import com.minisast.core.rules.RuleMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses Java source files and runs all applicable JavaAstRules.
 *
 * JavaParser produces a CompilationUnit (the AST root).
 * Each JavaAstRule receives the CU and returns its matches.
 *
 * Error handling strategy:
 *   - JavaParser returns problems alongside a partial AST.
 *   - We run rules on whatever was parsed (partial analysis > nothing).
 *   - We log parse problems at WARN level for visibility.
 *   - We throw ParseException only for complete parse failure (no AST at all).
 *
 * // Thread safety: JavaParser instances are NOT thread-safe.
 * // Each concurrent scan thread must use its own JavaLanguageParser instance.
 * // Phase 6 will use a ThreadLocal<JavaParser> or parser-per-thread pool.
 */
public final class JavaLanguageParser implements LanguageParser {

    private static final Logger log = LoggerFactory.getLogger(JavaLanguageParser.class);

    private final JavaParser javaParser;

    public JavaLanguageParser() {
        /*
         * Use JavaParser instance (not StaticJavaParser) because:
         *   StaticJavaParser.parse(File) → returns CompilationUnit directly, throws on error
         *   new JavaParser().parse(File) → returns ParseResult<CompilationUnit>
         *                                   giving us problems list + optional partial AST
         *
         * ParseResult is what we need for tolerant parsing — log problems, continue.
         * StaticJavaParser is a thin convenience wrapper that sacrifices error reporting.
         */
        ParserConfiguration config = new ParserConfiguration()
                .setLanguageLevel(ParserConfiguration.LanguageLevel.CURRENT);
        this.javaParser = new JavaParser(config);
    }

    @Override
    public Language getLanguage() {
        return Language.JAVA;
    }

    @Override
    public boolean supports(Path file) {
        return Language.fromPath(file)
                .map(lang -> lang == Language.JAVA)
                .orElse(false);
    }

    @Override
    public List<RuleMatch> analyze(Path file, List<Rule> rules) throws ParseException {
        log.debug("Parsing: {}", file);

        CompilationUnit cu = parse(file);

        // Extract only Java AST rules — skip any non-Java rules accidentally passed in
        List<JavaAstRule> javaRules = rules.stream()
                .filter(JavaAstRule.class::isInstance)
                .map(JavaAstRule.class::cast)
                .toList();

        String filePath = file.toAbsolutePath().toString();
        List<RuleMatch> matches = new ArrayList<>();

        for (JavaAstRule rule : javaRules) {
            try {
                List<RuleMatch> ruleMatches = rule.analyze(cu, filePath);
                matches.addAll(ruleMatches);
                log.debug("Rule {} found {} match(es) in {}",
                        rule.getId(), ruleMatches.size(), file.getFileName());
            } catch (Exception e) {
                // A rule crashing must not stop other rules from running
                log.warn("Rule {} threw an exception on {}: {}",
                        rule.getId(), file.getFileName(), e.getMessage());
            }
        }

        return matches;
    }

    private CompilationUnit parse(Path file) throws ParseException {
        try {
            ParseResult<CompilationUnit> result = javaParser.parse(file.toFile());

            // Log parse problems but continue with partial AST where possible
            if (!result.getProblems().isEmpty()) {
                result.getProblems().forEach(problem ->
                        log.warn("Parse problem in {}: {}", file.getFileName(), problem.getMessage())
                );
            }

            return result.getResult()
                    .orElseThrow(() -> new ParseException(
                            file.toString(),
                            "JavaParser returned no AST (complete parse failure)"
                    ));

        } catch (IOException e) {
            throw new ParseException(file.toString(), "Cannot read file", e);
        } catch (ParseException e) {
            throw e;
        } catch (Exception e) {
            throw new ParseException(
                    file.toString(), "Unexpected parser error: " + e.getMessage(), e);
        }
    }
}