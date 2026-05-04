// Test fixture — patterns caught by Phase 3 taint analysis
// Many of these are MISSED by Phase 2 (SqlInjectionRule)
package fixtures.vulnerable;

import java.sql.*;

public class TaintFlowSamples {

    // ── DETECTED BY JAVA-SQL-002 (taint rule) ─────────────────────────────

    // Pattern A: Variable aliasing — Phase 2 misses, Phase 3 catches
    // query is built from dynamic concat, then passed to sink as a named variable
    public void aliased_variable(Connection conn, String userId) throws SQLException {
        Statement stmt  = conn.createStatement();
        String query    = "SELECT * FROM users WHERE id = " + userId; // dynamic concat
        stmt.executeQuery(query);  // tainted variable at sink — MATCH
    }

    // Pattern B: HTTP source tracked through to sink
    // Phase 2 also catches the inline concat, Phase 3 adds HTTP source context
    public void from_http_request(
            javax.servlet.http.HttpServletRequest request,
            Connection conn
    ) throws SQLException {
        String userId = request.getParameter("id");      // HTTP_PARAMETER source
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = " + userId); // MATCH
    }

    // Pattern C: Full three-step flow — source → propagation → alias → sink
    // Phase 2 misses the alias, Phase 3 tracks the full path
    public void full_taint_flow(
            javax.servlet.http.HttpServletRequest request,
            Connection conn
    ) throws SQLException {
        String userId = request.getParameter("id");                     // HTTP source
        String query  = "SELECT * FROM users WHERE id = " + userId;    // propagation
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);  // aliased tainted var at sink — MATCH
    }

    // Pattern D: Multi-step propagation through two intermediate variables
    public void multi_step_propagation(
            javax.servlet.http.HttpServletRequest request,
            Connection conn
    ) throws Exception {
        String raw       = request.getParameter("search");               // HTTP source
        String processed = "item_" + raw;                               // taint propagates
        String query     = "SELECT * FROM items WHERE name = '" + processed + "'"; // taint propagates
        Statement stmt   = conn.createStatement();
        stmt.executeQuery(query);  // MATCH
    }

    // Pattern E: Aliased executeUpdate
    public void aliased_update(Connection conn, String name, String id) throws SQLException {
        Statement stmt = conn.createStatement();
        String sql     = "UPDATE users SET name = '" + name + "' WHERE id = " + id;
        stmt.executeUpdate(sql);  // MATCH
    }

    // ── SHOULD NOT BE DETECTED ─────────────────────────────────────────────

    // Safe: parameterized query — tainted input handled correctly
    public void safe_parameterized(
            javax.servlet.http.HttpServletRequest request,
            Connection conn
    ) throws SQLException {
        String userId = request.getParameter("id");                         // tainted
        PreparedStatement ps = conn.prepareStatement(                       // literal arg — safe
            "SELECT * FROM users WHERE id = ?"
        );
        ps.setInt(1, Integer.parseInt(userId));                             // not a SQL sink
    }

    // Safe: executeQuery with all-literal variable — not tainted
    public void safe_literal_variable(Connection conn) throws SQLException {
        String query = "SELECT * FROM users WHERE active = 1";              // literal only
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);                                            // query not tainted
    }
}