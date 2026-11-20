package com.mcpscanner.mcp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class LoopbackHostsTest {

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "LocalHost", "127.0.0.1", "::1", "[::1]"})
    void namesTheWellKnownLoopbackHosts(String host) {
        assertThat(LoopbackHosts.isNamedLoopback(host)).isTrue();
        assertThat(LoopbackHosts.isLoopback(host)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.2", "127.255.255.254", "[0:0:0:0:0:0:0:1]"})
    void otherLoopbackLiteralsAreLoopbackButNotNamed(String host) {
        assertThat(LoopbackHosts.isNamedLoopback(host)).isFalse();
        assertThat(LoopbackHosts.isLoopback(host)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"as.example.com", "10.0.0.1", "192.168.0.1", "128.0.0.1", "localhost.example.com",
            "127.0.0.1.example.com", "[fe80::1]", ""})
    void otherHostsAreNotLoopback(String host) {
        assertThat(LoopbackHosts.isLoopback(host)).isFalse();
    }

    @Test
    void nullIsNotLoopback() {
        assertThat(LoopbackHosts.isNamedLoopback(null)).isFalse();
        assertThat(LoopbackHosts.isLoopback(null)).isFalse();
    }
}
