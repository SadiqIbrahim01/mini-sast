// Test fixture — intentionally vulnerable code for SAST rule testing
// DO NOT use in production
package fixtures.vulnerable;

import java.sql.*;

public class SqlInjectionSamples {

    // ── SHOULD BE DETECTED ─────────────────────────────────────────────────

    // Case 1: Direct concatenation in executeQuery
    public void vulnerable_directConcat(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId); // line 14 → MATCH
    }

    // Case 2: executeUpdate with concat
    public void vulnerable_executeUpdate(Connection conn, String name) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.executeUpdate("UPDATE users SET name = '" + name + "'"); // line 20 → MATCH
    }

    // Case 3: prepareStatement with concat (dangerous — defeats purpose of prepare)
    public void vulnerable_prepareWithConcat(Connection conn, String table) throws SQLException {
        conn.prepareStatement("SELECT * FROM " + table + " WHERE 1=1"); // line 25 → MATCH
    }

    // ── SHOULD NOT BE DETECTED ─────────────────────────────────────────────

    // Safe: parameterized query
    public void safe_parameterized(Connection conn, int userId) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setInt(1, userId); // no match
    }

    // Safe: all-literal string (no variable)
    public void safe_literalOnly(Connection conn) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE active = 1"); // no match
    }
}