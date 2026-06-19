package com.mcpscanner.ui.state;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectPhaseTest {

    @Test
    void connectDisplayNameIsConnect() {
        assertThat(ConnectPhase.CONNECT.displayName()).isEqualTo("Connect");
    }

    @Test
    void oauthDisplayNameIsOAuth() {
        assertThat(ConnectPhase.OAUTH.displayName()).isEqualTo("OAuth");
    }
}
