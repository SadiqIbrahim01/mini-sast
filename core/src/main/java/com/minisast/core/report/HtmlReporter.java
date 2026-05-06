package com.minisast.core.report;

import com.minisast.core.model.*;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;

/**
 * Produces a self-contained HTML report with no external dependencies.
 *
 * Designed to be:
 *   - Emailed to clients or attached to Jira tickets
 *   - Opened offline in any browser
 *   - Printed as a PDF (print-friendly CSS included)
 *   - Shareable without infrastructure
 *
 * All CSS and JavaScript is embedded inline — one file, zero dependencies.
 * Interactive features: severity filtering, collapsible remediation sections.
 */
public final class HtmlReporter implements Reporter {

    private static final DateTimeFormatter DATE_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'")
                    .withZone(ZoneId.of("UTC"));

    @Override
    public String getFormat() { return "html"; }

    @Override
    public void report(ScanResult result, OutputStream output) throws IOException {
        PrintWriter out = new PrintWriter(output, true);
        out.println(buildHtml(result));
        out.flush();
    }

    private String buildHtml(ScanResult result) {
        StringBuilder html = new StringBuilder();
        ScanStats stats = result.stats();

        html.append("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
              <title>Mini SAST Security Report</title>
              <style>
                :root {
                  --critical: #dc2626; --critical-bg: #fef2f2;
                  --high:     #ea580c; --high-bg:     #fff7ed;
                  --medium:   #d97706; --medium-bg:   #fffbeb;
                  --low:      #2563eb; --low-bg:      #eff6ff;
                  --info:     #6b7280; --info-bg:     #f9fafb;
                  --bg:       #f8fafc;
                  --card:     #ffffff;
                  --border:   #e2e8f0;
                  --text:     #1e293b;
                  --muted:    #64748b;
                }
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
                       Roboto, sans-serif; background: var(--bg);
                       color: var(--text); line-height: 1.6; }
                header {
                  background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
                  color: white; padding: 2rem;
                }
                header h1 { font-size: 1.75rem; font-weight: 700;
                            letter-spacing: -0.02em; }
                header h1 span { color: #60a5fa; }
                header .meta { margin-top: 0.5rem; opacity: 0.8;
                               font-size: 0.875rem; }
                .container { max-width: 1100px; margin: 0 auto;
                             padding: 1.5rem 2rem; }
                .summary-grid { display: grid;
                  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                  gap: 1rem; margin: 1.5rem 0; }
                .summary-card { background: var(--card); border-radius: 0.75rem;
                  border: 1px solid var(--border); padding: 1.25rem;
                  text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.05); }
                .summary-card .count {
                  font-size: 2.5rem; font-weight: 800; line-height: 1; }
                .summary-card .label {
                  font-size: 0.75rem; font-weight: 600;
                  letter-spacing: 0.1em; margin-top: 0.25rem; }
                .card-critical .count, .card-critical .label
                  { color: var(--critical); }
                .card-high .count, .card-high .label
                  { color: var(--high); }
                .card-medium .count, .card-medium .label
                  { color: var(--medium); }
                .card-low .count, .card-low .label
                  { color: var(--low); }
                .card-info .count, .card-info .label
                  { color: var(--info); }
                .scan-meta { background: var(--card);
                  border: 1px solid var(--border); border-radius: 0.75rem;
                  padding: 1.25rem 1.5rem; margin-bottom: 1.5rem;
                  display: grid; grid-template-columns: 1fr 1fr;
                  gap: 0.5rem 2rem; font-size: 0.875rem; }
                .scan-meta dt { color: var(--muted); font-weight: 500; }
                .scan-meta dd { font-weight: 600; }
                .filters { display: flex; gap: 0.5rem;
                           flex-wrap: wrap; margin-bottom: 1rem; }
                .filter-btn { padding: 0.375rem 1rem; border-radius: 9999px;
                  border: 1px solid var(--border); background: var(--card);
                  cursor: pointer; font-size: 0.8rem; font-weight: 600;
                  transition: all 0.15s; }
                .filter-btn:hover { border-color: #94a3b8; }
                .filter-btn.active {
                  background: #0f172a; color: white; border-color: #0f172a; }
                .finding { background: var(--card); border: 1px solid var(--border);
                  border-radius: 0.75rem; margin-bottom: 0.75rem;
                  overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.04); }
                .finding-header { padding: 1rem 1.25rem;
                  display: flex; align-items: flex-start; gap: 0.75rem; }
                .severity-badge { padding: 0.2rem 0.6rem; border-radius: 0.375rem;
                  font-size: 0.7rem; font-weight: 700; letter-spacing: 0.08em;
                  flex-shrink: 0; margin-top: 0.15rem; }
                .badge-CRITICAL { background: var(--critical-bg);
                                  color: var(--critical); }
                .badge-HIGH     { background: var(--high-bg);
                                  color: var(--high); }
                .badge-MEDIUM   { background: var(--medium-bg);
                                  color: var(--medium); }
                .badge-LOW      { background: var(--low-bg);
                                  color: var(--low); }
                .badge-INFO     { background: var(--info-bg);
                                  color: var(--info); }
                .finding-title { font-weight: 700; font-size: 1rem; }
                .finding-location { font-size: 0.8rem; color: var(--muted);
                  font-family: 'SFMono-Regular', Consolas, monospace;
                  margin-top: 0.15rem; }
                .finding-body { padding: 0 1.25rem 1rem 1.25rem;
                  border-top: 1px solid var(--border); }
                .detail-grid { display: grid;
                  grid-template-columns: 120px 1fr;
                  gap: 0.4rem 0.75rem; font-size: 0.875rem;
                  padding-top: 0.75rem; }
                .detail-label { color: var(--muted); font-weight: 500; }
                .detail-value { word-break: break-word; }
                .tag { display: inline-block; padding: 0.1rem 0.5rem;
                  background: #f1f5f9; border-radius: 0.25rem;
                  font-size: 0.75rem; font-weight: 600; margin-right: 0.25rem; }
                .snippet { background: #0f172a; color: #e2e8f0;
                  border-radius: 0.375rem; padding: 0.6rem 0.875rem;
                  font-family: 'SFMono-Regular', Consolas, monospace;
                  font-size: 0.8rem; overflow-x: auto; margin-top: 0.25rem; }
                .remediation-toggle { background: none; border: none;
                  color: #2563eb; cursor: pointer; font-size: 0.8rem;
                  font-weight: 600; padding: 0; margin-top: 0.5rem; }
                .remediation-toggle:hover { text-decoration: underline; }
                .remediation-text { display: none; margin-top: 0.5rem;
                  font-size: 0.875rem; background: #f0fdf4;
                  border-left: 3px solid #22c55e; padding: 0.75rem 1rem;
                  border-radius: 0 0.375rem 0.375rem 0; }
                .no-findings { text-align: center; padding: 3rem;
                  color: var(--muted); }
                .no-findings .icon { font-size: 3rem; margin-bottom: 0.5rem; }
                footer { text-align: center; color: var(--muted);
                  font-size: 0.8rem; padding: 2rem; border-top: 1px solid var(--border);
                  margin-top: 2rem; }
                @media print {
                  .filters, .remediation-toggle { display: none; }
                  .remediation-text { display: block !important; }
                  .finding { break-inside: avoid; }
                }
              </style>
            </head>
            <body>
            """);

        // ── Header ────────────────────────────────────────────────────────────
        html.append("""
            <header>
              <div class="container">
                <h1>🔐 Mini <span>SAST</span> Security Report</h1>
                <div class="meta">
                  Generated: %s &nbsp;|&nbsp; Engine: %s
                </div>
              </div>
            </header>
            """.formatted(
                DATE_FMT.format(result.scanTimestamp()),
                result.engineVersion()
        ));

        html.append("<div class=\"container\">");

        // ── Summary cards ─────────────────────────────────────────────────────
        html.append("<div class=\"summary-grid\">");
        for (Severity s : new Severity[]{
                Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFO}) {
            long count = stats.countBySeverity(s);
            html.append("""
                <div class="summary-card card-%s">
                  <div class="count">%d</div>
                  <div class="label">%s</div>
                </div>
                """.formatted(
                    s.getLabel().toLowerCase(), count, s.getLabel()
            ));
        }
        html.append("</div>");

        // ── Scan metadata ─────────────────────────────────────────────────────
        html.append("""
            <dl class="scan-meta">
              <dt>Target</dt>
              <dd>%s</dd>
              <dt>Files Scanned</dt>
              <dd>%,d</dd>
              <dt>Lines Analysed</dt>
              <dd>%,d</dd>
              <dt>Duration</dt>
              <dd>%,d ms</dd>
            </dl>
            """.formatted(
                escapeHtml(result.targetPath()),
                stats.filesScanned(),
                stats.linesScanned(),
                result.durationMs()
        ));

        // ── Findings ──────────────────────────────────────────────────────────
        html.append("<h2 style=\"margin-bottom:0.75rem;font-size:1.1rem;\">Findings</h2>");

        if (!result.hasFindings()) {
            html.append("""
                <div class="no-findings">
                  <div class="icon">✅</div>
                  <div>No findings detected at or above the minimum severity threshold.</div>
                </div>
                """);
        } else {
            // Filter buttons
            html.append("<div class=\"filters\">");
            html.append("<button class=\"filter-btn active\" onclick=\"filter('all')\">All (%d)</button>"
                    .formatted(stats.totalFindings()));
            for (Severity s : new Severity[]{
                    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                    Severity.LOW, Severity.INFO}) {
                long count = stats.countBySeverity(s);
                if (count > 0) {
                    html.append(
                            "<button class=\"filter-btn\" onclick=\"filter('%s')\">%s (%d)</button>"
                                    .formatted(
                                            s.getLabel().toLowerCase(),
                                            s.getLabel(), count));
                }
            }
            html.append("</div>");

            // Finding cards sorted by severity descending
            List<Finding> sorted = result.findings().stream()
                    .sorted(Comparator.comparingInt(f -> -f.severity().getLevel()))
                    .toList();

            int idx = 0;
            for (Finding f : sorted) {
                html.append(buildFindingCard(f, idx++));
            }
        }

        html.append("</div>"); // container

        // ── Footer ────────────────────────────────────────────────────────────
        html.append("""
            <footer>
              Generated by <strong>Mini SAST</strong> v%s &mdash;
              Static Application Security Testing Tool
            </footer>
            """.formatted(result.engineVersion()));

        // ── JavaScript ────────────────────────────────────────────────────────
        html.append("""
            <script>
              function filter(severity) {
                document.querySelectorAll('.filter-btn').forEach(b =>
                  b.classList.remove('active'));
                event.target.classList.add('active');
                document.querySelectorAll('.finding').forEach(card => {
                  card.style.display =
                    (severity === 'all' || card.dataset.severity === severity)
                      ? '' : 'none';
                });
              }
              function toggleRemediation(id) {
                const el = document.getElementById('rem-' + id);
                const btn = document.getElementById('btn-' + id);
                if (el.style.display === 'none' || !el.style.display) {
                  el.style.display = 'block';
                  btn.textContent = '▲ Hide Remediation';
                } else {
                  el.style.display = 'none';
                  btn.textContent = '▼ Show Remediation';
                }
              }
            </script>
            """);

        html.append("</body></html>");
        return html.toString();
    }

    private String buildFindingCard(Finding f, int idx) {
        StringBuilder card = new StringBuilder();
        String sevLabel = f.severity().getLabel();

        card.append("<div class=\"finding\" data-severity=\"%s\">"
                .formatted(sevLabel.toLowerCase()));

        // Finding header
        card.append("""
            <div class="finding-header">
              <span class="severity-badge badge-%s">%s</span>
              <div>
                <div class="finding-title">%s</div>
                <div class="finding-location">%s</div>
              </div>
            </div>
            """.formatted(
                sevLabel, sevLabel,
                escapeHtml(f.ruleName()),
                escapeHtml(f.location().toString())
        ));

        // Finding body
        card.append("<div class=\"finding-body\"><div class=\"detail-grid\">");

        card.append(detailRow("Message", escapeHtml(f.message())));
        card.append(detailRow("Confidence", f.confidence().getLabel()));
        card.append(detailRow("Rule ID", f.ruleId()));

        if (!f.cwe().isBlank() || !f.owasp().isBlank()) {
            StringBuilder tags = new StringBuilder();
            if (!f.cwe().isBlank()) {
                tags.append("<span class=\"tag\">%s</span>".formatted(escapeHtml(f.cwe())));
            }
            if (!f.owasp().isBlank()) {
                tags.append("<span class=\"tag\">%s</span>".formatted(escapeHtml(f.owasp())));
            }
            card.append(detailRow("References", tags.toString()));
        }

        if (!f.location().snippet().isBlank()) {
            card.append(detailRow("Snippet",
                    "<div class=\"snippet\">%s</div>"
                            .formatted(escapeHtml(f.location().snippet()))));
        }

        card.append("</div>"); // detail-grid

        if (!f.remediation().isBlank()) {
            card.append("""
                <button class="remediation-toggle" id="btn-%d"
                        onclick="toggleRemediation(%d)">
                  ▼ Show Remediation
                </button>
                <div class="remediation-text" id="rem-%d">%s</div>
                """.formatted(idx, idx, idx, escapeHtml(f.remediation())));
        }

        card.append("</div></div>"); // finding-body + finding
        return card.toString();
    }

    private String detailRow(String label, String value) {
        return "<dt class=\"detail-label\">%s</dt><dd class=\"detail-value\">%s</dd>"
                .formatted(label, value);
    }

    private String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}