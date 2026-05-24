package com.minisast.core.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Loads and validates .minisast.yml project configuration files.
 *
 * DISCOVERY ORDER (auto-discovery mode):
 *   1. Target directory itself
 *   2. Parent directory
 *   3. Grandparent directory
 *   Stops at the first file found. This handles monorepos where the
 *   config lives at the repo root but the scan targets a subdirectory.
 *
 * SECURITY: uses SnakeYAML SafeConstructor behaviour by limiting
 *   alias expansion (prevents billion-laughs YAML bomb attacks).
 *   Never deserializes to arbitrary Java classes.
 *
 * VALIDATION: invalid severity strings are caught at ScanCommand level
 *   and reported as user errors, not exceptions. The loader itself is
 *   permissive — it does not validate field values, only structure.
 */
public final class ConfigLoader {

    private static final Logger log = LoggerFactory.getLogger(ConfigLoader.class);

    public  static final String CONFIG_FILE_NAME = ".minisast.yml";
    private static final int    MAX_DISCOVERY_DEPTH = 3;

    private ConfigLoader() {}

    /**
     * Load configuration from an explicit file path.
     *
     * @param configPath Absolute path to the config file
     * @return           Parsed MiniSastConfig
     * @throws IOException if the file cannot be read or parsed
     */
    public static MiniSastConfig load(Path configPath) throws IOException {
        log.info("Loading config from: {}", configPath);

        try (InputStream in = Files.newInputStream(configPath)) {
            LoaderOptions options = new LoaderOptions();
            options.setMaxAliasesForCollections(50); // YAML bomb prevention

            Yaml yaml = new Yaml(new Constructor(MiniSastConfig.class, options));
            MiniSastConfig config = yaml.load(in);

            // Empty file is valid — return defaults
            if (config == null) {
                log.debug("Config file is empty — using all defaults");
                return new MiniSastConfig();
            }

            log.debug("Config loaded: disabledRules={}, excludePatterns={}",
                    config.getRules().getDisable().size(),
                    config.getExclude().size());

            return config;

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(
                    "Failed to parse config file '%s': %s"
                            .formatted(configPath, e.getMessage()), e);
        }
    }

    /**
     * Auto-discovers a .minisast.yml by walking up from the scan target.
     *
     * @param scanTarget The file or directory being scanned
     * @return           Config if found, empty if no .minisast.yml exists
     */
    public static Optional<MiniSastConfig> discover(Path scanTarget) {
        Path dir = Files.isDirectory(scanTarget)
                ? scanTarget
                : scanTarget.getParent();

        for (int depth = 0; depth < MAX_DISCOVERY_DEPTH && dir != null; depth++) {
            Path candidate = dir.resolve(CONFIG_FILE_NAME);

            if (Files.exists(candidate) && Files.isReadable(candidate)) {
                try {
                    return Optional.of(load(candidate));
                } catch (IOException e) {
                    log.warn("Found {} but failed to load it: {}",
                            candidate, e.getMessage());
                    return Optional.empty(); // fail once, don't try parent
                }
            }

            dir = dir.getParent();
        }

        log.debug("No {} found — using CLI flags and defaults", CONFIG_FILE_NAME);
        return Optional.empty();
    }
}