package com.mcpscanner.auth.oauth.discovery;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class NetworkingSelectedChallengeSenderTest {

    private static final URI ENDPOINT = URI.create("http://127.0.0.1:18800/mcp");
    private static final Optional<ChallengeResponse> BURP_REPLY =
            Optional.of(new ChallengeResponse(401, Optional.of("Bearer")));
    private static final Optional<ChallengeResponse> DIRECT_REPLY =
            Optional.of(new ChallengeResponse(200, Optional.empty()));

    private final AtomicBoolean useBurpNetworking = new AtomicBoolean(true);
    private final ChallengeSender throughBurp = mock(ChallengeSender.class);
    private final ChallengeSender direct = mock(ChallengeSender.class);
    private final NetworkingSelectedChallengeSender sender =
            new NetworkingSelectedChallengeSender(useBurpNetworking::get, throughBurp, direct);

    @BeforeEach
    void stubSenders() {
        when(throughBurp.send(ENDPOINT)).thenReturn(BURP_REPLY);
        when(direct.send(ENDPOINT)).thenReturn(DIRECT_REPLY);
    }

    @Test
    void sendsThroughBurpWhenBurpNetworkingIsOn() {
        assertThat(sender.send(ENDPOINT)).isEqualTo(BURP_REPLY);
        verifyNoInteractions(direct);
    }

    @Test
    void sendsDirectlyWhenBurpNetworkingIsOff() {
        useBurpNetworking.set(false);

        assertThat(sender.send(ENDPOINT)).isEqualTo(DIRECT_REPLY);
        verifyNoInteractions(throughBurp);
    }

    @Test
    void aSettingChangedAtRuntimeAppliesToTheNextSend() {
        assertThat(sender.send(ENDPOINT)).isEqualTo(BURP_REPLY);

        useBurpNetworking.set(false);

        assertThat(sender.send(ENDPOINT)).isEqualTo(DIRECT_REPLY);
    }
}
