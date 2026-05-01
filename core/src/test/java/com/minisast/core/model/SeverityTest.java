package com.minisast.core.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Severity")
class SeverityTest {

    @Test
    @DisplayName("CRITICAL is above every other severity")
    void criticalAboveAll() {
        for (Severity s : Severity.values()) {
            assertThat(Severity.CRITICAL.isAtLeast(s))
                    .as("CRITICAL.isAtLeast(%s)", s)
                    .isTrue();
        }
    }

    @Test
    @DisplayName("INFO is below every other severity")
    void infoBelowAll() {
        for (Severity s : Severity.values()) {
            if (s != Severity.INFO) {
                assertThat(Severity.INFO.isAtLeast(s))
                        .as("INFO.isAtLeast(%s)", s)
                        .isFalse();
            }
        }
    }

    @ParameterizedTest(name = "{0}.isAtLeast({1}) == {2}")
    @CsvSource({
            "CRITICAL, CRITICAL, true",
            "CRITICAL, HIGH,     true",
            "CRITICAL, MEDIUM,   true",
            "CRITICAL, LOW,      true",
            "CRITICAL, INFO,     true",
            "HIGH,     CRITICAL, false",
            "HIGH,     HIGH,     true",
            "HIGH,     MEDIUM,   true",
            "MEDIUM,   HIGH,     false",
            "LOW,      MEDIUM,   false",
            "INFO,     INFO,     true"
    })
    @DisplayName("isAtLeast returns correct result")
    void isAtLeast(String severityName, String thresholdName, boolean expected) {
        assertThat(Severity.valueOf(severityName).isAtLeast(Severity.valueOf(thresholdName)))
                .isEqualTo(expected);
    }
}