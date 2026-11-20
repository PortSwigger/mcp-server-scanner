package com.mcpscanner.auth.oauth;

import org.junit.jupiter.api.Test;

import java.net.BindException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static com.mcpscanner.testutil.AwaitedFutures.valueWithin;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CallbackListenerTest {

    @Test
    void listensOnTheIpv6LoopbackLiteralItIsGiven() throws Exception {
        try (CallbackListener listener = CallbackListener.start("[::1]", 0, "/callback")) {
            HttpClient.newHttpClient().send(HttpRequest.newBuilder()
                    .uri(URI.create("http://[::1]:" + listener.port() + "/callback?code=abc&state=xyz"))
                    .timeout(Duration.ofSeconds(5)).GET().build(), HttpResponse.BodyHandlers.discarding());

            assertThat(callbackWithin(listener, Duration.ofSeconds(5)).code()).isEqualTo("abc");
        }
    }

    @Test
    void capturesAuthorizationResponseIssuer() throws Exception {
        try (CallbackListener listener = CallbackListener.start(0, "/callback")) {
            HttpClient.newHttpClient().send(HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + listener.port()
                            + "/callback?code=abc&state=xyz&iss=https%3A%2F%2Fissuer.example"))
                    .timeout(Duration.ofSeconds(5)).GET().build(), HttpResponse.BodyHandlers.discarding());

            assertThat(callbackWithin(listener, Duration.ofSeconds(5)).issuer())
                    .isEqualTo("https://issuer.example");
        }
    }

    @Test
    void resolvesFutureWithCodeAndStateOnCallback() throws Exception {
        try (CallbackListener listener = CallbackListener.start(0, "/callback")) {
            int port = listener.port();

            HttpResponse<String> response = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder()
                            .uri(URI.create("http://127.0.0.1:" + port + "/callback?code=abc&state=xyz"))
                            .timeout(Duration.ofSeconds(5))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            assertThat(response.statusCode()).isEqualTo(200);

            CallbackResult result = callbackWithin(listener, Duration.ofSeconds(5));
            assertThat(result.code()).isEqualTo("abc");
            assertThat(result.state()).isEqualTo("xyz");
            assertThat(result.isError()).isFalse();
        }
    }

    @Test
    void servesTheSuccessPageWhenItsOwnerClosesAsSoonAsTheCallbackArrives() throws Exception {
        try (CallbackListener listener = CallbackListener.start(0, "/callback")) {
            listener.awaitCallback().thenRunAsync(listener::close);

            HttpResponse<String> response = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder()
                            .uri(URI.create("http://127.0.0.1:" + listener.port() + "/callback?code=abc&state=xyz"))
                            .timeout(Duration.ofSeconds(5))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.body()).contains("Authorization complete");
        }
    }

    @Test
    void completesWithErrorParametersWhenAuthServerSignalsError() throws Exception {
        try (CallbackListener listener = CallbackListener.start(0, "/callback")) {
            int port = listener.port();

            HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder()
                            .uri(URI.create("http://127.0.0.1:" + port
                                    + "/callback?error=access_denied&error_description=user%20declined"))
                            .timeout(Duration.ofSeconds(5))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            CallbackResult result = callbackWithin(listener, Duration.ofSeconds(5));
            assertThat(result.isError()).isTrue();
            assertThat(result.error()).isEqualTo("access_denied");
            assertThat(result.errorDescription()).isEqualTo("user declined");
        }
    }

    @Test
    void closeIsIdempotentAcrossMultipleInvocations() throws Exception {
        CallbackListener listener = CallbackListener.start(0, "/callback");
        int port = listener.port();

        listener.close();
        listener.close();
        listener.close();

        assertThat(listener.isClosed()).isTrue();
        assertThatCode(() -> openServerSocket(port).close()).doesNotThrowAnyException();
    }

    @Test
    void canRebindSamePortAcrossManyRapidConnectCancelCycles() throws Exception {
        int port = pickFreeLoopbackPort();
        for (int i = 0; i < 10; i++) {
            CallbackListener listener = CallbackListener.start(port, "/callback");
            try {
                HttpClient.newHttpClient().send(
                        HttpRequest.newBuilder()
                                .uri(URI.create("http://127.0.0.1:" + port + "/callback?code=c" + i + "&state=s"))
                                .timeout(Duration.ofSeconds(5))
                                .GET()
                                .build(),
                        HttpResponse.BodyHandlers.ofString());
            } finally {
                listener.close();
            }
        }
    }

    @Test
    void canRebindSamePortImmediatelyAfterEstablishedConnection() throws Exception {
        int port = pickFreeLoopbackPort();

        CallbackListener first = CallbackListener.start(port, "/callback");
        try {
            HttpResponse<String> response = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder()
                            .uri(URI.create("http://127.0.0.1:" + port + "/callback?code=abc&state=xyz"))
                            .timeout(Duration.ofSeconds(5))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).isEqualTo(200);
        } finally {
            first.close();
        }

        try (CallbackListener second = CallbackListener.start(port, "/callback")) {
            assertThat(second.port()).isEqualTo(port);
        }
    }

    @Test
    void bindingToPortZeroExposesEphemeralPort() throws Exception {
        try (CallbackListener listener = CallbackListener.start(0, "/callback")) {
            assertThat(listener.port()).isGreaterThan(0);
        }
    }

    @Test
    void occupiedCallbackPortFailsAndCanBeUsedAfterRelease() throws Exception {
        int port;
        try (ServerSocket occupied = openServerSocket(0)) {
            port = occupied.getLocalPort();
            assertThatThrownBy(() -> CallbackListener.start(port, "/callback"))
                    .isInstanceOf(java.io.IOException.class);
        }

        try (CallbackListener listener = CallbackListener.start(port, "/callback")) {
            assertThat(listener.port()).isEqualTo(port);
        }
    }

    @Test
    void errorPageDoesNotDisplayUnvalidatedCallbackFields() throws Exception {
        try (CallbackListener listener = CallbackListener.start(0, "/callback")) {
            HttpResponse<String> response = HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder()
                            .uri(URI.create("http://127.0.0.1:" + listener.port()
                                    + "/callback?error=untrusted_error&error_description=untrusted_description"
                                    + "&state=wrong&iss=https%3A%2F%2Fattacker.example"))
                            .timeout(Duration.ofSeconds(5)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());

            assertThat(response.statusCode()).isEqualTo(400);
            assertThat(response.body()).contains("Authorization failed")
                    .doesNotContain("untrusted_error", "untrusted_description", "attacker.example");
        }
    }

    private static CallbackResult callbackWithin(CallbackListener listener, Duration bound) {
        return valueWithin(bound, listener.awaitCallback());
    }

    private static ServerSocket openServerSocket(int port) throws java.io.IOException {
        return new ServerSocket(port, 0, InetAddress.getByName("127.0.0.1"));
    }

    private static int pickFreeLoopbackPort() throws java.io.IOException {
        try (ServerSocket probe = new ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"))) {
            return probe.getLocalPort();
        }
    }
}
