package com.minisast.core.walker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses and applies .sastignore rules.
 *
 * File format is identical to .gitignore:
 *   - Lines starting with # are comments
 *   - Blank lines are skipped
 *   - * matches within one path segment
 *   - ** matches across path segments
 *
 * Security note: all pattern matching is against RELATIVE paths only.
 * Absolute path matching would allow patterns that escape the scan root.
 */
public final class IgnorePatterns {

    private static final Logger log = LoggerFactory.getLogger(IgnorePatterns.class);
    static final String IGNORE_FILE_NAME = ".sastignore";

    private final List<String> patterns;

    private IgnorePatterns(List<String> patterns) {
        this.patterns = List.copyOf(patterns);
    }

    public static IgnorePatterns empty() {
        return new IgnorePatterns(List.of());
    }

    public static IgnorePatterns loadFrom(Path directory) throws IOException {
        Path ignoreFile = directory.resolve(IGNORE_FILE_NAME);

        if (!Files.exists(ignoreFile)) {
            log.debug("No .sastignore found in: {}", directory);
            return empty();
        }

        List<String> patterns = new ArrayList<>();
        int lineNumber = 0;

        for (String line : Files.readAllLines(ignoreFile)) {
            lineNumber++;
            String trimmed = line.trim();

            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }

            // Reject patterns that look like path traversal attempts
            if (trimmed.contains("..")) {
                log.warn(".sastignore line {} contains '..', skipping: {}", lineNumber, trimmed);
                continue;
            }

            patterns.add(trimmed);
        }

        log.debug("Loaded {} ignore patterns from {}", patterns.size(), ignoreFile);
        return new IgnorePatterns(patterns);
    }

    /**
     * Returns true if the given relative path should be excluded from scanning.
     * @param relativePath Path relative to the scan root, using '/' separators.
     */
    public boolean matches(String relativePath) {
        String normalized = relativePath.replace('\\', '/');
        return patterns.stream().anyMatch(p -> globMatches(p, normalized));
    }

    public boolean isEmpty() {
        return patterns.isEmpty();
    }

    /**
     * Minimal glob matching:
     *   **  → matches any sequence of characters including '/'
     *   *   → matches any sequence of characters excluding '/'
     *   ?   → matches any single character
     */
    private boolean globMatches(String pattern, String path) {
        // Normalize pattern separators
        pattern = pattern.replace('\\', '/');

        // Convert glob to regex
        String regex = pattern
                .replace(".", "\\.")           // escape dots
                .replace("**", "\u0000")       // placeholder for **
                .replace("*", "[^/]*")         // * = any char except /
                .replace("\u0000", ".*")       // ** = any char including /
                .replace("?", "[^/]");         // ? = single non-/ char

        // Pattern matches if path equals pattern, or path starts with pattern (directory match)
        return path.matches(regex) || path.matches(regex + "/.*");
    }
}