package com.mcpscanner.signedin;

import com.mcpscanner.checks.api.BrowserConsentObservation;
import com.mcpscanner.checks.api.SignedInProbe;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class BrowserConsentObservationsTest {

    private static final URI AUTHORIZE = URI.create("https://auth.example.com/authorize");
    private static final URI OTHER = URI.create("https://other.example.com/authorize");

    private final BrowserConsentObservations observations = new BrowserConsentObservations();

    @Test
    void returnsWhatWasObservedAtTheAuthorizationEndpoint() {
        BrowserConsentObservation sameName = observation(AUTHORIZE, SignedInProbe.SAME_NAME);
        observations.record(sameName);
        observations.record(observation(OTHER, SignedInProbe.FRESH_NAME));

        assertThat(observations.at(AUTHORIZE)).containsExactly(sameName);
    }

    @Test
    void forgetsEverythingWhenCleared() {
        observations.record(observation(AUTHORIZE, SignedInProbe.SAME_NAME));
        observations.clear();

        assertThat(observations.at(AUTHORIZE)).isEmpty();
    }

    static BrowserConsentObservation observation(URI endpoint, SignedInProbe probe) {
        return new BrowserConsentObservation(probe, endpoint, "MCP Scanner", URI.create("http://localhost:4100/cb"),
                Optional.of(Duration.ofMillis(300)));
    }
}
