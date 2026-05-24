package com.minisast.core.engine;

import com.minisast.core.model.Confidence;
import com.minisast.core.model.Location;
import com.minisast.core.rules.RuleMatch;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SuppressionFilter")
class SuppressionFilterTest {

    @TempDir
    Path tempDir;

    private SuppressionFilter filter;

    @BeforeEach
    void setUp() { filter = new SuppressionFilter(); }

    // ── Same-line suppression ─────────────────────────────────────────────────

    @Test
    @DisplayName("Suppresses finding when same-line comment matches rule ID")
    void suppressesSameLineSpecificRule() throws IOException {
        Path file = write("""
            class T {
                void m() {
                    stmt.executeQuery(query); // minisast-ignore: JAVA-SQL-001
                }
            }
            """);

        RuleMatch match = matchAt(file, 3, "JAVA-SQL-001");
        List<RuleMatch> result = filter.filter(file, List.of(match));

        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("Suppresses finding when same-line comment has no rule ID (suppress all)")
    void suppressesSameLineAllRules() throws IOException {
        Path file = write("""
            class T {
                void m() {
                    stmt.executeQuery(query); // minisast-ignore
                }
            }
            """);

        RuleMatch match = matchAt(file, 3, "JAVA-SQL-001");
        assertThat(filter.filter(file, List.of(match))).isEmpty();
    }

    // ── Preceding-line suppression ────────────────────────────────────────────

    @Test
    @DisplayName("Suppresses finding when preceding line has suppression comment")
    void suppressesPrecedingLine() throws IOException {
        Path file = write("""
            class T {
                void m() {
                    // minisast-ignore: JAVA-SQL-001
                    stmt.executeQuery(query);
                }
            }
            """);

        RuleMatch match = matchAt(file, 4, "JAVA-SQL-001");
        assertThat(filter.filter(file, List.of(match))).isEmpty();
    }

    // ── Hash-style comments ───────────────────────────────────────────────────

    @Test
    @DisplayName("Suppresses finding with hash-style comment (config files)")
    void suppressesHashStyleComment() throws IOException {
        Path file = write("""
            # minisast-ignore: CONFIG-SEC-001
            DATABASE_PASSWORD=test_local_password_123
            """);

        RuleMatch match = matchAt(file, 2, "CONFIG-SEC-001");
        assertThat(filter.filter(file, List.of(match))).isEmpty();
    }

    // ── Rule ID specificity ───────────────────────────────────────────────────

    @Test
    @DisplayName("Does not suppress when comment specifies a different rule ID")
    void doesNotSuppressDifferentRule() throws IOException {
        Path file = write("""
            class T {
                void m() {
                    stmt.executeQuery(query); // minisast-ignore: JAVA-CMD-001
                }
            }
            """);

        RuleMatch match = matchAt(file, 3, "JAVA-SQL-001");
        List<RuleMatch> result = filter.filter(file, List.of(match));

        assertThat(result).hasSize(1);
    }

    @Test
    @DisplayName("Suppresses multiple rules listed in one comment")
    void suppressesMultipleRulesInOneComment() throws IOException {
        Path file = write("""
            class T {
                void m() {
                    doThing(); // minisast-ignore: JAVA-SQL-001, JAVA-SQL-002
                }
            }
            """);

        RuleMatch m1 = matchAt(file, 3, "JAVA-SQL-001");
        RuleMatch m2 = matchAt(file, 3, "JAVA-SQL-002");
        RuleMatch m3 = matchAt(file, 3, "JAVA-CMD-001");

        List<RuleMatch> result = filter.filter(file, List.of(m1, m2, m3));

        assertThat(result).hasSize(1);
        assertThat(result.get(0).ruleId()).isEqualTo("JAVA-CMD-001");
    }

    // ── No suppression cases ──────────────────────────────────────────────────

    @Test
    @DisplayName("Returns all matches when no suppression comments exist")
    void returnsAllMatchesWithNoSuppression() throws IOException {
        Path file = write("""
            class T {
                void m() {
                    stmt.executeQuery("SELECT..." + userId);
                }
            }
            """);

        RuleMatch match = matchAt(file, 3, "JAVA-SQL-001");
        assertThat(filter.filter(file, List.of(match))).hasSize(1);
    }

    @Test
    @DisplayName("Returns empty list unchanged when no matches")
    void returnsEmptyListUnchanged() throws IOException {
        Path file = write("class T {}");
        assertThat(filter.filter(file, List.of())).isEmpty();
    }

    // ── Unit test for comment parsing ─────────────────────────────────────────

    @ParameterizedTest(name = "Recognizes suppression: {0}")
    @ValueSource(strings = {
            "stmt.executeQuery(q); // minisast-ignore: JAVA-SQL-001",
            "stmt.executeQuery(q); // minisast-ignore",
            "// minisast-ignore: JAVA-SQL-001",
            "# minisast-ignore: JAVA-SQL-001",
            "  // minisast-ignore: JAVA-SQL-001  "
    })
    @DisplayName("hasSuppressionComment recognizes valid formats")
    void recognizesSuppressionFormats(String line) {
        assertThat(filter.hasSuppressionComment(line, "JAVA-SQL-001")).isTrue();
    }

    @ParameterizedTest(name = "Not a suppression: {0}")
    @ValueSource(strings = {
            "stmt.executeQuery(q); // some other comment",
            "stmt.executeQuery(q); // minisast-ignore: JAVA-CMD-001",
            "stmt.executeQuery(q);",
            ""
    })
    @DisplayName("hasSuppressionComment rejects non-matching lines")
    void rejectsNonMatchingLines(String line) {
        assertThat(filter.hasSuppressionComment(line, "JAVA-SQL-001")).isFalse();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Path write(String content) throws IOException {
        Path file = tempDir.resolve("Test.java");
        Files.writeString(file, content);
        return file;
    }

    private RuleMatch matchAt(Path file, int line, String ruleId) {
        return new RuleMatch(
                ruleId,
                Location.of(file.toAbsolutePath().toString(), line),
                "Test message",
                Confidence.HIGH
        );
    }
}