package com.minisast.core.config;

import java.util.*;

/**
 * Java model for .minisast.yml project configuration.
 *
 * Plain Java beans with getters/setters — SnakeYAML requires mutable
 * beans for deserialization. Records do not work with SnakeYAML's
 * reflection-based property mapping.
 *
 * All fields carry sensible defaults. An empty .minisast.yml is valid —
 * it just confirms the project has explicitly opted into using the tool.
 *
 * Key names in YAML are camelCase to match SnakeYAML's default
 * property resolution (no custom constructor needed):
 *   minimumSeverity → setMinimumSeverity()
 *   failOnFindings  → setFailOnFindings()
 */
public class MiniSastConfig {

    private String       version = "1.0";
    private ScanSection  scan    = new ScanSection();
    private RulesSection rules   = new RulesSection();
    private OutputSection output = new OutputSection();
    private List<String> exclude = new ArrayList<>();

    // ── Getters + setters ─────────────────────────────────────────────────────

    public String       getVersion()  { return version; }
    public ScanSection  getScan()     { return scan; }
    public RulesSection getRules()    { return rules; }
    public OutputSection getOutput()  { return output; }
    public List<String> getExclude()  { return exclude; }

    public void setVersion(String v)        { this.version = v; }
    public void setScan(ScanSection s)      { this.scan    = s; }
    public void setRules(RulesSection r)    { this.rules   = r; }
    public void setOutput(OutputSection o)  { this.output  = o; }
    public void setExclude(List<String> e)  { this.exclude = e; }

    // ── Nested sections ───────────────────────────────────────────────────────

    public static class ScanSection {
        private String  minimumSeverity = "LOW";
        private boolean failOnFindings  = false;
        private String  failOnSeverity  = null;
        private int     maxFileSizeMb   = 10;

        public String  getMinimumSeverity() { return minimumSeverity; }
        public boolean isFailOnFindings()   { return failOnFindings; }
        public String  getFailOnSeverity()  { return failOnSeverity; }
        public int     getMaxFileSizeMb()   { return maxFileSizeMb; }

        public void setMinimumSeverity(String v) { this.minimumSeverity = v; }
        public void setFailOnFindings(boolean v) { this.failOnFindings  = v; }
        public void setFailOnSeverity(String v)  { this.failOnSeverity  = v; }
        public void setMaxFileSizeMb(int v)      { this.maxFileSizeMb   = v; }
    }

    public static class RulesSection {
        private List<String>               disable  = new ArrayList<>();
        private Map<String, RuleOverride>  override = new LinkedHashMap<>();

        public List<String>              getDisable()  { return disable; }
        public Map<String, RuleOverride> getOverride() { return override; }

        public void setDisable(List<String> d)               { this.disable  = d; }
        public void setOverride(Map<String, RuleOverride> o) { this.override = o; }
    }

    public static class RuleOverride {
        private String  severity = null;  // override rule severity
        private Boolean enabled  = null;  // override enabled flag

        public String  getSeverity() { return severity; }
        public Boolean getEnabled()  { return enabled; }

        public void setSeverity(String s)  { this.severity = s; }
        public void setEnabled(Boolean e)  { this.enabled  = e; }
    }

    public static class OutputSection {
        private String format = "cli";
        private String file   = null;

        public String getFormat() { return format; }
        public String getFile()   { return file; }

        public void setFormat(String f) { this.format = f; }
        public void setFile(String f)   { this.file   = f; }
    }
}