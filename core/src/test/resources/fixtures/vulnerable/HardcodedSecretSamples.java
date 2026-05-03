// Test fixture — intentionally vulnerable and safe code for SAST rule testing
// DO NOT use in production
package fixtures.vulnerable;

public class HardcodedSecretSamples {

    // ── SHOULD BE DETECTED ─────────────────────────────────────────────────

    // Real-looking secrets — sensitive name + sufficient entropy
    private String password = "superSecret123!";                          // line 8  → MATCH HIGH
    private String apiKey   = "sk-abc123def456ghi789jkl012345678901";    // line 9  → MATCH HIGH
    private static final String DB_PASS = "X9#mK2$pL8@vR4nQ";           // line 10 → MATCH HIGH              // line 10 → MATCH MEDIUM

    public void setCredentials() {
        String token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";       // line 14 → MATCH HIGH
        this.password = "anotherSecret99!XyZ";                           // line 15 → MATCH HIGH
    }

    // ── SHOULD NOT BE DETECTED ─────────────────────────────────────────────

    // Safe: reads from environment — not a literal
    private String envPassword  = System.getenv("DB_PASSWORD");          // line 19 → no match

    // Safe: empty string
    private String emptySecret  = "";                                    // line 22 → no match

    // Safe: too short to be a real secret
    private String shortPass    = "abc";                                 // line 25 → no match

    // Safe: curly brace template placeholder
    private String apiKeyTpl    = "{YOUR_API_KEY_HERE}";                 // line 28 → no match

    // Safe: curly brace with different wording
    private String passwordTpl  = "{YOUR_PASSWORD_HERE}";               // line 31 → no match

    // Safe: dollar-sign template (common in config files and docs)
    private String dbPassTpl    = "${DB_PASSWORD}";                      // line 34 → no match

    // Safe: square bracket placeholder
    private String tokenTpl     = "[INSERT_TOKEN_HERE]";                 // line 37 → no match

    // Safe: instruction verb in value
    private String apiKeyInstr  = "REPLACE_WITH_YOUR_API_KEY";          // line 40 → no match

    // Safe: instruction verb — insert
    private String secretInstr  = "INSERT_SECRET_HERE";                 // line 43 → no match

    // Safe: all-caps instruction pattern
    private String keyAllCaps   = "ADD_YOUR_KEY_HERE";                  // line 46 → no match

    // Safe: repeated characters (obviously fake)
    private String repeatedKey  = "xxxxxxxxxxxxxxxx";                   // line 49 → no match

    // Safe: sequential characters (obviously fake)
    private String seqKey       = "abcdefghijklmnop";                   // line 52 → no match

    // Safe: variable name is not sensitive, value has no known pattern
    private String description  = "this is a long description string!"; // line 55 → no match

    // Safe: word "password" as exact value (existing check)
    private String pw           = "password";                           // line 58 → no match (too common)

    // Safe: low entropy despite sensitive name
    // "mypassword" reads as English — entropy ~3.0, below HIGH threshold
    // This is a deliberate suppression — test code commonly does this
    private String testPassword = "mypassword";                         // line 62 → no match (low entropy)
}