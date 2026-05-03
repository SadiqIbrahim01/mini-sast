package com.minisast.core.model;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

public enum Language {

    JAVA      ("Java",       Set.of(".java")),
    PYTHON    ("Python",     Set.of(".py")),
    JAVASCRIPT("JavaScript", Set.of(".js", ".mjs", ".cjs")),
    TYPESCRIPT("TypeScript", Set.of(".ts", ".tsx")),

    /**
     * CONFIG covers all key=value and structured config formats.
     * These are handled by ConfigFileParser, not AST parsers.
     *
     * Notable inclusions:
     *   .env        — dotenv files (should never be committed with real values)
     *   .properties — Spring Boot, Java app config
     *   .yml/.yaml  — Spring Boot, Docker Compose, Kubernetes
     *   .toml       — Rust, Python (pyproject.toml), general config
     *   .ini        — Legacy config files
     *   .conf       — Generic config files
     */
    CONFIG    ("Config",     Set.of(
            ".env",
            ".properties",
            ".yml", ".yaml",
            ".toml",
            ".ini",
            ".conf"
    )),

    UNKNOWN   ("Unknown",    Set.of());

    private final String      displayName;
    private final Set<String> extensions;

    Language(String displayName, Set<String> extensions) {
        this.displayName = displayName;
        this.extensions  = Set.copyOf(extensions);
    }

    public String      getDisplayName()   { return displayName; }
    public Set<String> getExtensions()    { return extensions; }

    public static Optional<Language> fromPath(Path file) {
        String fileName = file.getFileName().toString();
        int dot = fileName.lastIndexOf('.');
        if (dot == -1) {
            // Handle dotfiles with no extension: .env, .envrc
            if (fileName.startsWith(".env")) return Optional.of(Language.CONFIG);
            return Optional.empty();
        }
        String ext = fileName.substring(dot).toLowerCase();
        return Arrays.stream(values())
                .filter(lang -> lang.extensions.contains(ext))
                .findFirst();
    }
}