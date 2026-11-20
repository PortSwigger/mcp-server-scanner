package com.mcpscanner.checks.catalog.outboundrequest;

import burp.api.montoya.http.message.HttpHeader;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ProbeUserInfoTest {

    private static final ProbeUserInfo USER_INFO_PROBE = ProbeUserInfo.of("https://example.com@a.oob.test/");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void recognisesBasicAuthorizationBuiltFromTheProbesUserInfo() {
        assertThat(USER_INFO_PROBE.supplied(authorization("Basic " + base64("example.com:")))).isTrue();
        assertThat(USER_INFO_PROBE.supplied(authorization("basic " + base64("example.com")))).isTrue();
    }

    @Test
    void recognisesTheUserInfoOfAnIpv6BaseHost() {
        assertThat(ProbeUserInfo.of("https://[::1]@a.oob.test/x").supplied(authorization("Basic " + base64("[::1]:"))))
                .isTrue();
    }

    @Test
    void treatsOtherCredentialsAsForwarded() {
        assertThat(USER_INFO_PROBE.supplied(authorization("Basic " + base64("service:s3cret")))).isFalse();
        assertThat(USER_INFO_PROBE.supplied(authorization("Bearer " + base64("example.com:")))).isFalse();
        assertThat(USER_INFO_PROBE.supplied(authorization("Basic !!not-base64"))).isFalse();
        assertThat(USER_INFO_PROBE.supplied(header("Proxy-Authorization",
                "Basic " + base64("example.com:")))).isFalse();
    }

    @Test
    void suppliesNothingForAProbeWithoutUserInfo() {
        assertThat(ProbeUserInfo.of("http://a.oob.test").supplied(authorization("Basic " + base64(":")))).isFalse();
        assertThat(ProbeUserInfo.of("--server=http://a.oob.test/").supplied(authorization("Basic " + base64("x:"))))
                .isFalse();
    }

    private static HttpHeader authorization(String value) {
        return header("Authorization", value);
    }

    private static HttpHeader header(String name, String value) {
        return OutboundFixtures.post("http://a.oob.test/", Map.of(name, value), "").headers().stream()
                .filter(header -> header.name().equals(name)).findFirst().orElseThrow();
    }

    private static String base64(String credentials) {
        return Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }
}
