package com.mcpscanner.checks;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

class HostReachabilityTest {

    @Test
    void treatsNullOrBlankAsNotLocallyReachable() {
        assertThat(HostReachability.isLocallyReachable(null)).isFalse();
        assertThat(HostReachability.isLocallyReachable("")).isFalse();
        assertThat(HostReachability.isLocallyReachable("   ")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "LOCALHOST", "LocalHost", "service.localhost"})
    void treatsLocalhostNamesAsLocallyReachable(String host) {
        assertThat(HostReachability.isLocallyReachable(host)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "127.5.5.5", "::1"})
    void treatsLoopbackIpsAsLocallyReachable(String host) {
        assertThat(HostReachability.isLocallyReachable(host)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"10.0.0.5", "10.255.255.255"})
    void treatsTenSlashEightAsLocallyReachable(String host) {
        assertThat(HostReachability.isLocallyReachable(host)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"172.16.0.1", "172.31.255.254"})
    void recognisesRfc1918172Range(String host) {
        // 172.16.0.0/12 is RFC1918 private, not CGNAT. True CGNAT (100.64.0.0/10)
        // is covered separately.
        assertThat(HostReachability.isLocallyReachable(host)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"172.15.0.1", "172.32.0.1"})
    void rejectsHostsOutsideOneSeventyTwoSlashTwelve(String host) {
        assertThat(HostReachability.isLocallyReachable(host)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"100.64.0.5", "100.127.255.255"})
    void recognisesCgnatRange(String host) {
        // RFC 6598: 100.64.0.0/10 is the Carrier-Grade NAT shared address space.
        // MCP servers behind a CGNAT-style edge are still reachable from inside
        // the same private fabric and must be treated as locally reachable for
        // severity calibration.
        assertThat(HostReachability.isLocallyReachable(host)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"100.63.255.255", "100.128.0.1"})
    void rejectsHostsOutsideOneHundredSlashTen(String host) {
        assertThat(HostReachability.isLocallyReachable(host)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"fc00::1", "fd12:3456:789a::1", "FD00::1"})
    void recognisesIpv6UniqueLocalAddress(String host) {
        // RFC 4193: fc00::/7 (so fc00::/8 unassigned + fd00::/8 locally assigned)
        // is the IPv6 Unique Local Address space — the IPv6 equivalent of RFC1918.
        assertThat(HostReachability.isLocallyReachable(host)).isTrue();
    }

    @Test
    void treatsOneNinetyTwoSlashSixteenAsLocallyReachable() {
        assertThat(HostReachability.isLocallyReachable("192.168.1.1")).isTrue();
    }

    @Test
    void treatsLinkLocalAsLocallyReachable() {
        assertThat(HostReachability.isLocallyReachable("169.254.1.1")).isTrue();
    }

    @Test
    void treatsWildcardZeroAddressAsNotLocallyReachable() {
        // 0.0.0.0 is a wildcard bind, not a loopback — treat as public.
        assertThat(HostReachability.isLocallyReachable("0.0.0.0")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"8.8.8.8", "mcp.example.com"})
    void treatsPublicAddressesAsNotLocallyReachable(String host) {
        assertThat(HostReachability.isLocallyReachable(host)).isFalse();
    }
}
