package com.minisast.core.walker;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.*;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

@DisplayName("FileWalker")
class FileWalkerTest {

    @TempDir
    Path tempDir;

    private FileWalker walker;

    @BeforeEach
    void setUp() {
        walker = FileWalker.withDefaults();
    }

    @Test
    @DisplayName("Discovers all files in a flat directory")
    void findsAllFilesInFlatDirectory() throws IOException {
        Files.createFile(tempDir.resolve("Foo.java"));
        Files.createFile(tempDir.resolve("Bar.java"));
        Files.createFile(tempDir.resolve("config.yml"));

        List<Path> files = walker.walk(tempDir);

        assertThat(files).hasSize(3);
    }

    @Test
    @DisplayName("Recurses into subdirectories")
    void recursesIntoSubdirectories() throws IOException {
        Path sub = Files.createDirectory(tempDir.resolve("service"));
        Files.createFile(tempDir.resolve("Main.java"));
        Files.createFile(sub.resolve("Service.java"));

        List<Path> files = walker.walk(tempDir);

        assertThat(files).hasSize(2);
    }

    @Test
    @DisplayName("Skips .git directory")
    void skipsGitDirectory() throws IOException {
        Files.createFile(tempDir.resolve("Main.java"));
        Path gitDir = Files.createDirectory(tempDir.resolve(".git"));
        Files.createFile(gitDir.resolve("config"));

        List<Path> files = walker.walk(tempDir);

        assertThat(files)
                .hasSize(1)
                .extracting(p -> p.getFileName().toString())
                .containsExactly("Main.java");
    }

    @Test
    @DisplayName("Skips node_modules directory")
    void skipsNodeModules() throws IOException {
        Files.createFile(tempDir.resolve("index.js"));
        Path nodeModules = Files.createDirectory(tempDir.resolve("node_modules"));
        Files.createFile(nodeModules.resolve("lodash.js"));

        List<Path> files = walker.walk(tempDir);

        assertThat(files).hasSize(1);
    }

    @Test
    @DisplayName("Skips target directory (Maven output)")
    void skipsTargetDirectory() throws IOException {
        Files.createFile(tempDir.resolve("App.java"));
        Path target = Files.createDirectory(tempDir.resolve("target"));
        Files.createFile(target.resolve("App.class"));

        List<Path> files = walker.walk(tempDir);

        assertThat(files).hasSize(1);
    }

    @Test
    @DisplayName("Returns single file when given a file path")
    void singleFilePassthrough() throws IOException {
        Path file = Files.createFile(tempDir.resolve("Single.java"));

        List<Path> files = walker.walk(file);

        assertThat(files).containsExactly(file.toAbsolutePath().normalize());
    }

    @Test
    @DisplayName("Throws IllegalArgumentException for nonexistent path")
    void throwsForNonExistentPath() {
        Path missing = tempDir.resolve("does-not-exist");

        assertThatThrownBy(() -> walker.walk(missing))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("does not exist");
    }

    @Test
    @DisplayName("Handles empty directory gracefully")
    void handlesEmptyDirectory() throws IOException {
        List<Path> files = walker.walk(tempDir);
        assertThat(files).isEmpty();
    }
}