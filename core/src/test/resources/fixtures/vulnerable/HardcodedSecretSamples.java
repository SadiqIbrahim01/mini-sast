// Test fixture — intentionally vulnerable code
package fixtures.vulnerable;

public class HardcodedSecretSamples {

    // ── SHOULD BE DETECTED ─────────────────────────────────────────────────

    private String password = "superSecret123!";            // line 7  → MATCH
    private String apiKey   = "sk-abc123def456ghi789jkl";  // line 8  → MATCH
    private static final String DB_PASS = "hunter2hunter2"; // line 9  → MATCH

    public void setCredentials() {
        String token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"; // line 13 → MATCH
        this.password = "anotherSecret99!";                         // line 14 → MATCH
    }

    // ── SHOULD NOT BE DETECTED ─────────────────────────────────────────────

    private String password_env  = System.getenv("DB_PASSWORD");   // no match — not a literal
    private String emptyPassword = "";                              // no match — empty
    private String shortPass     = "abc";                           // no match — too short
    private String placeholder   = "changeme";                      // no match — placeholder
    private String notSensitive  = "hello world, this is a string"; // no match — not sensitive name
}