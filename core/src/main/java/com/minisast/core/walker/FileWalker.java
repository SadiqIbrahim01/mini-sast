package com.minisast.core.walker;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Recursively discovers files eligible for scanning.
 *
 * Security concerns addressed:
 *   1. MAX_FILE_SIZE_BYTES — prevents memory exhaustion on huge files
 *   2. MAX_DEPTH          — prevents infinite recursion via symlinks
 *   3. FOLLOW_LINKS OFF   — prevents escaping the scan root via symlink
 *   4. DEFAULT_IGNORED_DIRS — skips directories that should never be scanned
 *   5. visitFileFailed()  — logs access errors, never crashes the scan
 *
 * All decisions are logged at DEBUG level for auditability.
 */
public final class FileWalker {

    private static final Logger log = LoggerFactory.getLogger(FileWalker.class);

    static final long MAX_FILE_SIZE_BYTES = 10L * 1024 * 1024; // 10 MB
    static final int  MAX_DEPTH           = 50;

    private static final Set<String> DEFAULT_IGNORED_DIRS = Set.of(
            ".git", ".svn", ".hg",
            "node_modules",
            "target", "build", "dist", "out",
            ".idea", ".vscode", ".eclipse",
            "__pycache__", ".mypy_cache", ".pytest_cache",
            ".gradle", "vendor", ".bundle"
    );

    private final IgnorePatterns ignorePatterns;

    public FileWalker(IgnorePatterns ignorePatterns) {
        this.ignorePatterns = ignorePatterns;
    }

    public static FileWalker withDefaults() {
        return new FileWalker(IgnorePatterns.empty());
    }

    /**
     * Walk a file or directory and return all files eligible for scanning.
     *
     * @param root  A file (returns just that file) or directory (recursive walk)
     * @return      Ordered list of absolute Paths to scan
     * @throws IllegalArgumentException if the path does not exist
     * @throws IOException              if the filesystem walk fails
     */
    public List<Path> walk(Path root) throws IOException {
        if (!Files.exists(root)) {
            throw new IllegalArgumentException("Scan target does not exist: " + root);
        }

        // Single file fast path
        if (Files.isRegularFile(root)) {
            log.debug("Single file scan: {}", root);
            return List.of(root.toAbsolutePath().normalize());
        }

        log.debug("Walking directory: {}", root);
        List<Path> collected = new ArrayList<>();

        // Note: no FOLLOW_LINKS — prevents directory traversal via symlinks
        Files.walkFileTree(root, Set.of(), MAX_DEPTH, new SimpleFileVisitor<>() {

            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                // Never follow symlinked directories
                if (attrs.isSymbolicLink()) {
                    log.debug("Skipping symlinked directory: {}", dir);
                    return FileVisitResult.SKIP_SUBTREE;
                }

                String dirName = dir.getFileName() != null
                        ? dir.getFileName().toString()
                        : "";

                if (DEFAULT_IGNORED_DIRS.contains(dirName)) {
                    log.debug("Skipping default-ignored directory: {}", dir);
                    return FileVisitResult.SKIP_SUBTREE;
                }

                String relative = toRelative(root, dir);
                if (!relative.isEmpty() && ignorePatterns.matches(relative)) {
                    log.debug("Skipping .sastignore directory: {}", dir);
                    return FileVisitResult.SKIP_SUBTREE;
                }

                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (attrs.isSymbolicLink()) {
                    log.debug("Skipping symlinked file: {}", file);
                    return FileVisitResult.CONTINUE;
                }

                if (attrs.size() > MAX_FILE_SIZE_BYTES) {
                    log.warn("Skipping oversized file ({} bytes): {}", attrs.size(), file);
                    return FileVisitResult.CONTINUE;
                }

                String relative = toRelative(root, file);
                if (ignorePatterns.matches(relative)) {
                    log.debug("Skipping .sastignore file: {}", file);
                    return FileVisitResult.CONTINUE;
                }

                collected.add(file.toAbsolutePath().normalize());
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                // Log and continue — one unreadable file must not abort the scan
                log.warn("Cannot access file (skipping): {} — {}", file, exc.getMessage());
                return FileVisitResult.CONTINUE;
            }
        });

        log.info("File walk complete: {} files found under {}", collected.size(), root);
        return collected;
    }

    private String toRelative(Path root, Path path) {
        try {
            return root.relativize(path).toString().replace('\\', '/');
        } catch (IllegalArgumentException e) {
            return path.toString();
        }
    }
}