package com.minisast.core.model;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

/**
 * Languages Mini SAST can analyze.
 *
 * Architecture decision: each Language owns its file extensions.
 * No switch statements scattered across the codebase.
 * Adding Python support later = add PYTHON enum value. Nothing else changes.
 */
public enum Language {

    JAVA      ("Java",       Set.of(".java")),
    PYTHON    ("Python",     Set.of(".py")),
    JAVASCRIPT("JavaScript", Set.of(".js", ".mjs", ".cjs")),
    TYPESCRIPT("TypeScript", Set.of(".ts", ".tsx")),
    UNKNOWN   ("Unknown",    Set.of());

    private final String displayName;
    private final Set<String> extensions;

    Language(String displayName, Set<String> extensions) {
        this.displayName = displayName;
        this.extensions  = Set.copyOf(extensions);
    }

    public String getDisplayName()   { return displayName; }
    public Set<String> getExtensions() { return extensions; }

    public static Optional<Language> fromPath(Path file) {
        String fileName = file.getFileName().toString();
        int dot = fileName.lastIndexOf('.');
        if (dot == -1) return Optional.empty();

        String ext = fileName.substring(dot).toLowerCase();
        return Arrays.stream(values())
                .filter(lang -> lang.extensions.contains(ext))
                .findFirst();
    }
}