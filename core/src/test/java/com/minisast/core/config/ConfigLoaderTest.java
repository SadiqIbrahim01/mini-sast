package com.minisast.core.config;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

@DisplayName("ConfigLoader")
class ConfigLoaderTest {

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("Loads full config with all sections")
    void loadsFullConfig() throws IOException {
        Path config = writeConfig("""
            version: "1.0"
            scan:
              minimumSeverity: HIGH
              failOnFindings: true
              failOnSeverity: CRITICAL
            rules:
              disable:
                - JAVA-SQL-002
                - JAVA-CMD-001
            output:
              format: json
              file: report.json
            exclude:
              - "**/test/**"
              - "**/generated/**"
            """);

        MiniSastConfig result = ConfigLoader.load(config);

        assertThat(result.getScan().getMinimumSeverity()).isEqualTo("HIGH");
        assertThat(result.getScan().isFailOnFindings()).isTrue();
        assertThat(result.getScan().getFailOnSeverity()).isEqualTo("CRITICAL");
        assertThat(result.getRules().getDisable())
                .containsExactly("JAVA-SQL-002", "JAVA-CMD-001");
        assertThat(result.getOutput().getFormat()).isEqualTo("json");
        assertThat(result.getOutput().getFile()).isEqualTo("report.json");
        assertThat(result.getExclude())
                .containsExactly("**/test/**", "**/generated/**");
    }

    @Test
    @DisplayName("Empty config file returns all defaults")
    void emptyConfigReturnsDefaults() throws IOException {
        Path config = writeConfig("");

        MiniSastConfig result = ConfigLoader.load(config);

        assertThat(result.getScan().getMinimumSeverity()).isEqualTo("LOW");
        assertThat(result.getScan().isFailOnFindings()).isFalse();
        assertThat(result.getRules().getDisable()).isEmpty();
        assertThat(result.getExclude()).isEmpty();
    }

    @Test
    @DisplayName("Partial config uses defaults for missing fields")
    void partialConfigUsesDefaults() throws IOException {
        Path config = writeConfig("""
            scan:
              minimumSeverity: MEDIUM
            """);

        MiniSastConfig result = ConfigLoader.load(config);

        assertThat(result.getScan().getMinimumSeverity()).isEqualTo("MEDIUM");
        assertThat(result.getScan().isFailOnFindings()).isFalse(); // default
        assertThat(result.getRules().getDisable()).isEmpty();      // default
    }

    @Test
    @DisplayName("Config with only rules section")
    void configWithDisabledRulesOnly() throws IOException {
        Path config = writeConfig("""
            rules:
              disable:
                - JAVA-SQL-001
            """);

        MiniSastConfig result = ConfigLoader.load(config);
        assertThat(result.getRules().getDisable()).containsExactly("JAVA-SQL-001");
        assertThat(result.getScan().getMinimumSeverity()).isEqualTo("LOW");
    }

    @Test
    @DisplayName("Discovers .minisast.yml in target directory")
    void discoversConfigInTargetDirectory() throws IOException {
        writeConfig(tempDir.resolve(ConfigLoader.CONFIG_FILE_NAME), """
            scan:
              minimumSeverity: HIGH
            """);

        Optional<MiniSastConfig> result = ConfigLoader.discover(tempDir);

        assertThat(result).isPresent();
        assertThat(result.get().getScan().getMinimumSeverity()).isEqualTo("HIGH");
    }

    @Test
    @DisplayName("Returns empty when no .minisast.yml exists")
    void returnsEmptyWhenNoConfigFile() {
        Optional<MiniSastConfig> result = ConfigLoader.discover(tempDir);
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("Discovers config in parent directory")
    void discoversConfigInParentDirectory() throws IOException {
        writeConfig(tempDir.resolve(ConfigLoader.CONFIG_FILE_NAME), """
            scan:
              minimumSeverity: CRITICAL
            """);
        Path subDir = Files.createDirectory(tempDir.resolve("src"));

        Optional<MiniSastConfig> result = ConfigLoader.discover(subDir);

        assertThat(result).isPresent();
        assertThat(result.get().getScan().getMinimumSeverity()).isEqualTo("CRITICAL");
    }

    @Test
    @DisplayName("Throws IOException for malformed YAML")
    void throwsForMalformedYaml() throws IOException {
        Path config = writeConfig("scan: {invalid: yaml: content:");

        assertThatThrownBy(() -> ConfigLoader.load(config))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Failed to parse");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Path writeConfig(String content) throws IOException {
        return writeConfig(tempDir.resolve("config.yml"), content);
    }

    private Path writeConfig(Path path, String content) throws IOException {
        Files.writeString(path, content);
        return path;
    }
}