package com.minisast.core.engine;

import com.minisast.core.rules.RuleMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Filters RuleMatches suppressed by inline source comments.
 *
 * SUPPRESSION FORMATS:
 *
 *   // minisast-ignore: JAVA-SQL-001    suppress specific rule on this line
 *   // minisast-ignore                  suppress all rules on this line
 *   # minisast-ignore: CONFIG-SEC-001   hash-style (config files, Python)
 *
 * PLACEMENT — comment can appear on:
 *   a) The same line as the vulnerable code
 *      String q = buildQuery(id); // minisast-ignore: JAVA-SQL-001
 *
 *   b) The line immediately above the vulnerable code
 *      // minisast-ignore: JAVA-SQL-001
 *      stmt.executeQuery(q);
 *
 * DESIGN: suppression is a conscious developer decision. Every suppression
 * is logged at INFO level so it appears in verbose output and can be
 * audited in CI logs. This prevents suppression comments from silently
 * hiding real vulnerabilities without any trace.
 *
 * FAIL OPEN: if the file cannot be read for suppression checking (e.g.,
 * race condition, permission change), all matches are returned unfiltered.
 * Better to report a possible false positive than to silently suppress a
 * real finding because of a file read error.
 */
public final class SuppressionFilter {

    private static final Logger log = LoggerFactory.getLogger(SuppressionFilter.class);
    private static final String IGNORE_TOKEN = "minisast-ignore";

    /**
     * @param file    The source file being scanned
     * @param matches All rule matches for this file
     * @return        Matches not suppressed by inline comments
     */
    public List<RuleMatch> filter(Path file, List<RuleMatch> matches) {
        if (matches.isEmpty()) return matches;

        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            // Fail open — log and return all matches
            log.debug("Cannot read lines for suppression check on {}: {}", file, e.getMessage());
            return matches;
        }

        List<RuleMatch> filtered = matches.stream()
                .filter(match -> !isSuppressed(match, lines, file))
                .toList();

        int suppressedCount = matches.size() - filtered.size();
        if (suppressedCount > 0) {
            log.info("Suppressed {} finding(s) via inline comments in {}",
                    suppressedCount, file.getFileName());
        }

        return filtered;
    }

    private boolean isSuppressed(RuleMatch match, List<String> lines, Path file) {
        int line = match.location().startLine(); // 1-based

        // Check the finding's own line (suppression at end of line)
        if (isLineInRange(line, lines)) {
            if (hasSuppressionComment(lines.get(line - 1), match.ruleId())) {
                log.info("  Suppressed [{}] at {}:{} (same-line comment)",
                        match.ruleId(), file.getFileName(), line);
                return true;
            }
        }

        // Check the line immediately above (suppression on preceding line)
        int prevLine = line - 1;
        if (isLineInRange(prevLine, lines)) {
            if (hasSuppressionComment(lines.get(prevLine - 1), match.ruleId())) {
                log.info("  Suppressed [{}] at {}:{} (preceding-line comment)",
                        match.ruleId(), file.getFileName(), line);
                return true;
            }
        }

        return false;
    }

    /**
     * Returns true if the line contains a suppression comment for ruleId.
     *
     * "minisast-ignore"              → suppress ALL rules (ruleId irrelevant)
     * "minisast-ignore: JAVA-SQL-001" → suppress ONLY JAVA-SQL-001
     * "minisast-ignore: JAVA-SQL-001, JAVA-SQL-002" → suppress multiple
     */
    boolean hasSuppressionComment(String line, String ruleId) {
        int idx = line.indexOf(IGNORE_TOKEN);
        if (idx == -1) return false;

        String afterToken = line.substring(idx + IGNORE_TOKEN.length()).trim();

        // "minisast-ignore" alone (nothing after, or comment char after)
        if (afterToken.isEmpty()
                || afterToken.startsWith("//")
                || afterToken.startsWith("#")
                || afterToken.startsWith("*/")) {
            return true; // suppress all rules
        }

        // "minisast-ignore: RULE_ID" or "minisast-ignore: RULE_ID1, RULE_ID2"
        if (afterToken.startsWith(":")) {
            String ruleList = afterToken.substring(1).trim();
            String[] specifiedRules = ruleList.split("[,\\s]+");
            for (String specified : specifiedRules) {
                if (specified.trim().equalsIgnoreCase(ruleId)) {
                    return true;
                }
            }
        }

        return false;
    }

    private boolean isLineInRange(int lineNum, List<String> lines) {
        return lineNum >= 1 && lineNum <= lines.size();
    }
}