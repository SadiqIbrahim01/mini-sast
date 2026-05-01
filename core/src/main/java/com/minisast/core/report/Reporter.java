package com.minisast.core.report;

import com.minisast.core.model.ScanResult;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Contract for output formatters.
 *
 * Using OutputStream (not Writer, not String) because:
 *   - Callers control the destination: stdout, file, HTTP response body, etc.
 *   - Avoids encoding issues (binary formats like PDF need OutputStream anyway)
 *   - Easy to test: pass new ByteArrayOutputStream()
 *
 * Phase 4 implementations: CliReporter, JsonReporter, HtmlReporter
 */
public interface Reporter {
    String getFormat(); // "cli" | "json" | "html"
    void report(ScanResult result, OutputStream output) throws IOException;
}