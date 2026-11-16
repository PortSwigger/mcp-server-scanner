package com.mcpscanner.scan;

import com.mcpscanner.mcp.ScannerSentinels;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SendToConnectionPolicyTest {

    private static final Map<String, String> CAPABILITY = Map.of(ScannerSentinels.AUDIT_CAPABILITY_HEADER, "signed");
    private static final Map<String, String> CREDENTIALS = Map.of("Authorization", "Bearer fresh",
            "Mcp-Session-Id", "session-1", "MCP-Protocol-Version", "2025-06-18");

    private final AtomicBoolean handleAuthentication = new AtomicBoolean();
    private final AtomicInteger credentialReads = new AtomicInteger();
    private final SendToConnectionPolicy policy = new SendToConnectionPolicy(handleAuthentication::get,
            () -> ScanConnection.unbound(baseline -> CAPABILITY), () -> {
                credentialReads.incrementAndGet();
                return CREDENTIALS;
            });

    @Test
    void handledAuthenticationAddsOnlyTheCapabilityHeader() {
        handleAuthentication.set(true);

        assertThat(policy.get().headers(Map.of())).isEqualTo(CAPABILITY);
        assertThat(credentialReads).hasValue(0);
    }

    @Test
    void unhandledAuthenticationWritesCurrentCredentialsWithoutTheCapabilityHeader() {
        Map<String, String> headers = policy.get().headers(Map.of());

        assertThat(headers).isEqualTo(CREDENTIALS).doesNotContainKey(ScannerSentinels.AUDIT_CAPABILITY_HEADER);
    }

    @Test
    void unhandledAuthenticationReadsCredentialsAtHandoffTime() {
        ScanConnection connection = policy.get();
        assertThat(credentialReads).hasValue(0);

        connection.headers(Map.of());

        assertThat(credentialReads).hasValue(1);
    }

    @Test
    void settingIsHonouredOnTheNextHandoffWithoutReconnecting() {
        assertThat(policy.get().headers(Map.of())).isEqualTo(CREDENTIALS);

        handleAuthentication.set(true);

        assertThat(policy.get().headers(Map.of())).isEqualTo(CAPABILITY);
    }

    @Test
    void unhandledAuthenticationStillRejectsAStaleConnection() {
        SendToConnectionPolicy stale = new SendToConnectionPolicy(() -> false,
                () -> new ScanConnection(baseline -> CAPABILITY, () -> {
                    throw new IllegalStateException("connection changed");
                }), () -> CREDENTIALS);

        assertThatThrownBy(() -> stale.get().requireCurrent()).hasMessage("connection changed");
    }

    @Test
    void reportsWhetherBurpToolRequestsAreHandledByTheExtension() {
        assertThat(policy.handlesAuthentication()).isFalse();

        handleAuthentication.set(true);

        assertThat(policy.handlesAuthentication()).isTrue();
    }
}
