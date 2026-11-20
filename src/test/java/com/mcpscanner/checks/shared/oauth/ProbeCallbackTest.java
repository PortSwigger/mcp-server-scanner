package com.mcpscanner.checks.shared.oauth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ProbeCallbackTest {

    private static final URI CALLBACK = ProbeCallback.loopback("scancheck-test");

    @Test
    void mintsLoopbackCallbacksOnTheScannerPort() {
        assertThat(CALLBACK).isEqualTo(URI.create("http://127.0.0.1:49151/scancheck-test"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://127.0.0.1:4000/callback", "http://127.0.0.1/callback"})
    void aScannerOnTheIpv4LoopbackPutsTheProbesOnTheIpv6LoopbackLiteral(String scannerRedirect) {
        assertThat(ProbeCallback.hostUnrelatedTo(Optional.of(URI.create(scannerRedirect)))).isEqualTo("[::1]");
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://LocalHost:4000/callback", "http://[::1]:4000/callback"})
    void anyOtherScannerHostPutsTheProbesOnTheIpv4LoopbackLiteral(String scannerRedirect) {
        assertThat(ProbeCallback.hostUnrelatedTo(Optional.of(URI.create(scannerRedirect)))).isEqualTo("127.0.0.1");
    }

    @Test
    void anUnknownScannerRedirectPutsTheProbesOnTheIpv6LoopbackLiteral() {
        assertThat(ProbeCallback.hostUnrelatedTo(Optional.empty())).isEqualTo("[::1]");
    }

    @Test
    void matchesTheSameSchemeHostPortAndPathWhateverTheQuery() {
        assertThat(ProbeCallback.matches(CALLBACK, URI.create("http://127.0.0.1:49151/scancheck-test?code=c")))
                .isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://user@127.0.0.1:49151/scancheck-test?code=c",
            "https://127.0.0.1:49151/scancheck-test?code=c", "http://127.0.0.1:49152/scancheck-test?code=c",
            "http://127.0.0.1:49151/scancheck-test/x?code=c", "/scancheck-test?code=c"})
    void rejectsAnythingElse(String location) {
        assertThat(ProbeCallback.matches(CALLBACK, URI.create(location))).isFalse();
    }

    @Test
    void readsTheSingleCodeDeliveredWithTheExpectedState() {
        assertThat(ProbeCallback.response(CALLBACK, URI.create(CALLBACK + "?code=c1&state=s1"), "s1"))
                .flatMap(CallbackResponse::code).contains("c1");
    }

    @Test
    void readsAnErrorDeliveredWithTheExpectedState() {
        assertThat(ProbeCallback.response(CALLBACK, URI.create(CALLBACK + "#error=access_denied&state=s1"), "s1"))
                .hasValueSatisfying(response -> assertThat(response.code()).isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"?code=c1&state=other", "?code=c1", "?code=c1&code=c2&state=s1",
            "?code=c1&error=x&state=s1", "?state=s1", "?code=c1&state=s1&state=s1"})
    void rejectsAResponseThatIsNotOneOutcomeForTheExpectedState(String query) {
        assertThat(ProbeCallback.response(CALLBACK, URI.create(CALLBACK + query), "s1")).isEmpty();
    }

    @Test
    void keepsAQueryTheCallbackWasRegisteredWith() {
        URI registered = URI.create("http://127.0.0.1:49151/cb?tenant=t");

        assertThat(ProbeCallback.response(registered, URI.create(registered + "&code=c&state=s"), "s")).isPresent();
        assertThat(ProbeCallback.response(registered, URI.create("http://127.0.0.1:49151/cb?code=c&state=s"), "s"))
                .isEmpty();
    }

    @Test
    void mintsLoopbackCallbacksOnAGivenHost() {
        assertThat(ProbeCallback.loopback("localhost", "scancheck-test"))
                .isEqualTo(URI.create("http://localhost:49151/scancheck-test"));
    }
}
