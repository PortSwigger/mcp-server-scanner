package com.mcpscanner.scan.field;

import org.junit.jupiter.api.Test;

import static com.mcpscanner.scan.field.MetaEnvelopeRegistry.Role.CARRIER;
import static com.mcpscanner.scan.field.MetaEnvelopeRegistry.Role.PASSENGER;
import static org.assertj.core.api.Assertions.assertThat;

class MetaEnvelopeRegistryTest {

    private final MetaEnvelopeRegistry registry = new MetaEnvelopeRegistry();

    @Test
    void anUnknownBodyHasItsEnvelopeFuzzed() {
        assertThat(registry.fuzzesEnvelopeOf("manual request")).isTrue();
    }

    @Test
    void aPassengerHasItsEnvelopeLeftAlone() {
        registry.hold("body", PASSENGER);

        assertThat(registry.fuzzesEnvelopeOf("body")).isFalse();
    }

    @Test
    void aCarrierHasItsEnvelopeFuzzed() {
        registry.hold("body", CARRIER);

        assertThat(registry.fuzzesEnvelopeOf("body")).isTrue();
    }

    @Test
    void aBodyAnotherScanCarriesIsFuzzedEvenWhileAScanHoldsItAsAPassenger() {
        registry.hold("body", PASSENGER);
        registry.hold("body", CARRIER);

        assertThat(registry.fuzzesEnvelopeOf("body")).isTrue();

        registry.release("body", CARRIER);
        assertThat(registry.fuzzesEnvelopeOf("body")).isFalse();
    }

    @Test
    void aPassengerHeldByTwoScansStaysUnfuzzedUntilBothRelease() {
        registry.hold("body", PASSENGER);
        registry.hold("body", PASSENGER);

        registry.release("body", PASSENGER);
        assertThat(registry.fuzzesEnvelopeOf("body")).isFalse();

        registry.release("body", PASSENGER);
        assertThat(registry.fuzzesEnvelopeOf("body")).isTrue();
    }

    @Test
    void releasingAnUnknownBodyChangesNothing() {
        registry.release("never held", PASSENGER);
        registry.hold("other", PASSENGER);
        registry.release("never held", CARRIER);

        assertThat(registry.fuzzesEnvelopeOf("never held")).isTrue();
        assertThat(registry.fuzzesEnvelopeOf("other")).isFalse();
    }

    @Test
    void forgetsTheOldestBodiesOnceTheLimitIsPassedSoTheyFallBackToBeingFuzzed() {
        for (int i = 0; i <= MetaEnvelopeRegistry.REMEMBERED; i++) {
            registry.hold("body " + i, PASSENGER);
        }

        assertThat(registry.fuzzesEnvelopeOf("body 0")).isTrue();
        assertThat(registry.fuzzesEnvelopeOf("body " + MetaEnvelopeRegistry.REMEMBERED)).isFalse();
    }
}
