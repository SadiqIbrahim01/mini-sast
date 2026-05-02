// Test fixture — intentionally vulnerable code
package fixtures.vulnerable;

public class CommandInjectionSamples {

    // ── SHOULD BE DETECTED ─────────────────────────────────────────────────

    public void vulnerable_runtimeExec(String userInput) throws Exception {
        Runtime.getRuntime().exec("ping " + userInput);  // line 9 → MATCH
    }

    public void vulnerable_processBuilder(String filename) {
        new ProcessBuilder("ls", filename);  // line 13 → MATCH (MEDIUM confidence)
    }

    // ── SHOULD NOT BE DETECTED ─────────────────────────────────────────────

    public void safe_literalOnly() throws Exception {
        Runtime.getRuntime().exec("ls -la");  // no match — literal only
    }
}