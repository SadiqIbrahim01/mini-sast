package com.minisast.core.report;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Creates Reporter instances based on format string.
 *
 * Single responsibility: format name → Reporter implementation.
 * Called by ScanCommand and (in Phase 7) the REST API.
 *
 * Unknown formats fall back to CLI reporter with a warning rather
 * than throwing — a scanner that crashes on an unknown format flag
 * provides no value. The user still gets results.
 */
public final class ReporterFactory {

    private static final Logger log = LoggerFactory.getLogger(ReporterFactory.class);

    private ReporterFactory() {} // utility class

    /**
     * @param format   "cli", "json", or "html" (case-insensitive)
     * @param useColor Whether to emit ANSI colour codes (CLI reporter only)
     */
    public static Reporter forFormat(String format, boolean useColor) {
        return switch (format.toLowerCase().trim()) {
            case "json" -> new JsonReporter();
            case "html" -> new HtmlReporter();
            case "cli"  -> new CliReporter(useColor);
            default -> {
                log.warn("Unknown output format '{}' — defaulting to cli", format);
                yield new CliReporter(useColor);
            }
        };
    }

    /** Supported format names for help text and validation */
    public static String supportedFormats() {
        return "cli, json, html";
    }
}