package com.minisast.core.rules.java;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.minisast.core.model.Confidence;
import com.minisast.core.model.Severity;
import com.minisast.core.rules.RuleMatch;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SqlInjectionRule")
class SqlInjectionRuleTest {

    private SqlInjectionRule rule;

    @BeforeEach
    void setUp() { rule = new SqlInjectionRule(); }

    @Test
    @DisplayName("Rule metadata is correctly defined")
    void ruleMetadata() {
        assertThat(rule.getId()).isEqualTo("JAVA-SQL-001");
        assertThat(rule.getSeverity()).isEqualTo(Severity.CRITICAL);
        assertThat(rule.getCwe()).isEqualTo("CWE-89");
        assertThat(rule.getLanguage()).isEqualTo("java");
        assertThat(rule.isEnabled()).isTrue();
    }

    @Test
    @DisplayName("Detects direct string concatenation in executeQuery")
    void detectsDirectConcatenation() {
        String code = """
            class Test {
                void vuln(java.sql.Statement stmt, String id) throws Exception {
                    stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
                }
            }
            """;
        List<RuleMatch> matches = analyze(code);
        assertThat(matches).hasSize(1);
        assertThat(matches.get(0).ruleId()).isEqualTo("JAVA-SQL-001");
        assertThat(matches.get(0).confidence()).isEqualTo(Confidence.HIGH);
    }

    @Test
    @DisplayName("Detects concatenation in executeUpdate")
    void detectsExecuteUpdate() {
        String code = """
            class Test {
                void vuln(java.sql.Statement stmt, String name) throws Exception {
                    stmt.executeUpdate("UPDATE users SET name = '" + name + "'");
                }
            }
            """;
        assertThat(analyze(code)).hasSize(1);
    }

    @Test
    @DisplayName("Does not flag parameterized queries")
    void ignoresParameterizedQuery() {
        String code = """
            class Test {
                void safe(java.sql.Connection conn) throws Exception {
                    var ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
                    ps.setInt(1, 42);
                }
            }
            """;
        assertThat(analyze(code)).isEmpty();
    }

    @Test
    @DisplayName("Does not flag all-literal SQL strings")
    void ignoresLiteralOnlyString() {
        String code = """
            class Test {
                void safe(java.sql.Statement stmt) throws Exception {
                    stmt.executeQuery("SELECT * FROM users WHERE active = 1");
                }
            }
            """;
        assertThat(analyze(code)).isEmpty();
    }

    @Test
    @DisplayName("Detects concatenation nested inside multi-part expression")
    void detectsNestedConcatenation() {
        String code = """
            class Test {
                void vuln(java.sql.Statement stmt, String col, String val) throws Exception {
                    stmt.executeQuery("SELECT " + col + " FROM t WHERE v = " + val);
                }
            }
            """;
        assertThat(analyze(code)).hasSize(1);
    }

    private List<RuleMatch> analyze(String code) {
        CompilationUnit cu = StaticJavaParser.parse(code);
        return rule.analyze(cu, "Test.java");
    }
}