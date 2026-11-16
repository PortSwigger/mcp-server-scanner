package com.mcpscanner.checks.shared.collaborator;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class InteractionWindowTest {

    @Test
    void theStandardWindowSettlesAfterThreeSecondsPollingOncePerMinute() {
        assertThat(InteractionWindow.standard())
                .isEqualTo(new InteractionWindow(Duration.ofSeconds(3), Duration.ofSeconds(60)));
    }

    @Test
    void refusesAPollIntervalThatIsNotPositive() {
        assertThatThrownBy(() -> new InteractionWindow(Duration.ZERO, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
