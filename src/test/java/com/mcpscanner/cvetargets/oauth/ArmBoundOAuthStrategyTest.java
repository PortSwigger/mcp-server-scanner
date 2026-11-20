package com.mcpscanner.cvetargets.oauth;

import com.mcpscanner.auth.AccessToken;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.grant.ClientType;
import com.mcpscanner.auth.grant.LiveRefreshGrant;
import com.mcpscanner.auth.grant.OAuthClient;
import com.mcpscanner.auth.grant.RefreshGrant;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ArmBoundOAuthStrategyTest {

    private static final URI ARM = URI.create("http://127.0.0.1:41000/mcp");
    private static final RefreshGrant GRANT = new RefreshGrant(URI.create("http://127.0.0.1:41000"),
            Optional.of(ARM), new OAuthClient("client-1", Optional.empty(), ClientType.PUBLIC), "refresh-1",
            List.of("mcp:tools"));

    private final OAuthAuthCodeStrategy live = mock(OAuthAuthCodeStrategy.class);
    private final ArmBoundOAuthStrategy strategy = new ArmBoundOAuthStrategy(endpoint -> live);

    @Test
    void handsOverTheCurrentAccessTokenAndTheLiveRefreshGrant() {
        holding(Optional.of(GRANT));

        OAuthSessionHandover handover = bound().handOver();

        assertThat(handover.accessToken()).isEqualTo("access-1");
        assertThat(handover.grant()).contains(GRANT);
    }

    @Test
    void handsOverASessionWithoutARefreshTokenAsItsAccessTokenAlone() {
        holding(Optional.empty());

        assertThat(bound().handOver().grant()).isEmpty();
    }

    @Test
    void afterTheHandoverTheHarnessNeverRefreshesOrLeasesTheGrant() {
        holding(Optional.of(GRANT));
        bound().handOver();

        assertThat(strategy.supportsRefresh()).isFalse();
        assertThat(strategy.refresh()).isFalse();
        assertThat(strategy.refreshGrantStore()).isEmpty();
        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer access-1");
        verify(live, never()).refresh();
        verify(live, never()).headers();
    }

    @Test
    void aSessionIsHandedOverOnlyOnce() {
        holding(Optional.of(GRANT));
        bound().handOver();

        assertThatThrownBy(strategy::handOver).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void neverPrintsTheHandedOverTokens() {
        assertThat(new OAuthSessionHandover("access-1", Optional.of(GRANT)).toString())
                .doesNotContain("access-1", "refresh-1");
    }

    @SuppressWarnings("unchecked")
    private void holding(Optional<RefreshGrant> grant) {
        when(live.currentToken()).thenReturn(Optional.of(
                AccessToken.of("access-1", Instant.now().plus(Duration.ofHours(1)))));
        when(live.withExclusiveGrant(any())).thenAnswer(leasing -> grant.map(held ->
                ((Function<LiveRefreshGrant, Object>) leasing.getArgument(0)).apply(new LiveRefreshGrant() {
                    @Override
                    public RefreshGrant grant() {
                        return held;
                    }

                    @Override
                    public void adopt(com.mcpscanner.auth.grant.IssuedTokens tokens) {
                        throw new AssertionError("the harness never adopts tokens");
                    }
                })));
    }

    private ArmBoundOAuthStrategy bound() {
        strategy.bind(ARM, Duration.ofSeconds(1));
        return strategy;
    }
}
