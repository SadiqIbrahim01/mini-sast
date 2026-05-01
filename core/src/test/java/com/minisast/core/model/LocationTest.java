package com.minisast.core.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

@DisplayName("Location")
class LocationTest {

    @Test
    @DisplayName("Location.of(file, line) creates valid single-line location")
    void ofSingleLine() {
        Location loc = Location.of("src/main/Foo.java", 42);

        assertThat(loc.filePath()).isEqualTo("src/main/Foo.java");
        assertThat(loc.startLine()).isEqualTo(42);
        assertThat(loc.endLine()).isEqualTo(42);
        assertThat(loc.snippet()).isEmpty();
    }

    @Test
    @DisplayName("toString returns file:line format")
    void toStringFormat() {
        Location loc = Location.of("src/Bar.java", 10);
        assertThat(loc.toString()).isEqualTo("src/Bar.java:10");
    }

    @Test
    @DisplayName("Rejects blank filePath")
    void rejectsBlankFilePath() {
        assertThatThrownBy(() -> Location.of("", 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("filePath");
    }

    @Test
    @DisplayName("Rejects null filePath")
    void rejectsNullFilePath() {
        assertThatThrownBy(() -> Location.of(null, 1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Rejects line 0 (lines are 1-based)")
    void rejectsLineZero() {
        assertThatThrownBy(() -> Location.of("Foo.java", 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("startLine");
    }

    @Test
    @DisplayName("Rejects endLine < startLine")
    void rejectsEndBeforeStart() {
        assertThatThrownBy(() -> new Location("Foo.java", 10, 5, 0, 0, ""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("endLine");
    }
}