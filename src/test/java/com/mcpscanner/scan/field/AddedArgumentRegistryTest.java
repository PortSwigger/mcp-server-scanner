package com.mcpscanner.scan.field;

import com.mcpscanner.scan.ArgumentPath;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AddedArgumentRegistryTest {

    private final AddedArgumentRegistry registry = new AddedArgumentRegistry();

    @Test
    void forgetsTheOldestBodiesOnceTheLimitIsPassed() {
        for (int i = 0; i <= AddedArgumentRegistry.REMEMBERED; i++) {
            registry.record("body " + i, ArgumentPath.of("a"));
        }

        assertThat(registry.isProbe("body 0")).isFalse();
        assertThat(registry.isProbe("body " + AddedArgumentRegistry.REMEMBERED)).isTrue();
    }

    @Test
    void releaseDropsOnlyThatBody() {
        registry.record("body", ArgumentPath.of("a"));

        registry.record("other", ArgumentPath.of("b"));
        registry.release("body");

        assertThat(registry.addedTo("body")).isEmpty();
        assertThat(registry.isProbe("body")).isFalse();
        assertThat(registry.isProbe("other")).isTrue();
    }

    @Test
    void aBodyRecordedByTwoScansStaysAProbeUntilBothHaveReleasedIt() {
        registry.record("body", ArgumentPath.of("a"));
        registry.record("body", ArgumentPath.of("a"));

        registry.release("body");
        assertThat(registry.isProbe("body")).isTrue();

        registry.release("body");
        assertThat(registry.isProbe("body")).isFalse();
    }

    @Test
    void releasingAnUnknownBodyChangesNothing() {
        registry.release("never recorded");

        assertThat(registry.isProbe("never recorded")).isFalse();
    }
}
