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
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CallbackListenerTest {

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

            CallbackResult result = listener.awaitCallback().get(5, TimeUnit.SECONDS);
            assertThat(result.code()).isEqualTo("abc");
            assertThat(result.state()).isEqualTo("xyz");
            assertThat(result.isError()).isFalse();
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

            CallbackResult result = listener.awaitCallback().get(5, TimeUnit.SECONDS);
            assertThat(result.isError()).isTrue();
            assertThat(result.error()).isEqualTo("access_denied");
            assertThat(result.errorDescription()).isEqualTo("user declined");
        }
    }

    @Test
    void closeAllReleasesAllActiveListeners() throws Exception {
        CallbackListener first = CallbackListener.start(0, "/callback");
        CallbackListener second = CallbackListener.start(0, "/callback");
        int firstPort = first.port();
        int secondPort = second.port();

        assertThatThrownBy(() -> openServerSocket(firstPort)).isInstanceOf(BindException.class);
        assertThatThrownBy(() -> openServerSocket(secondPort)).isInstanceOf(BindException.class);

        CallbackListener.closeAll();

        assertThatCode(() -> openServerSocket(firstPort).close()).doesNotThrowAnyException();
        assertThatCode(() -> openServerSocket(secondPort).close()).doesNotThrowAnyException();
    }

    @Test
    void closeRemovesFromRegistry() throws Exception {
        CallbackListener listener = CallbackListener.start(0, "/callback");
        int port = listener.port();

        listener.close();
        CallbackListener.closeAll();

        assertThatCode(() -> openServerSocket(port).close()).doesNotThrowAnyException();
    }

    @Test
    void closeIsIdempotentAcrossMultipleInvocations() throws Exception {
        CallbackListener listener = CallbackListener.start(0, "/callback");
        int port = listener.port();

        listener.close();
        listener.close();
        listener.close();
        CallbackListener.closeAll();

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
                CallbackListener.closeAll();
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
    void errorPageEscapesScriptInError() {
        CallbackResult result = new CallbackResult(null, null, "<script>alert(1)</script>", null);

        String html = CallbackListener.errorPage(result);

        assertThat(html).contains("&lt;script&gt;alert(1)&lt;/script&gt;");
        assertThat(html).doesNotContain("<script>alert(1)</script>");
    }

    @Test
    void errorPageEscapesImgInErrorDescription() {
        CallbackResult result = new CallbackResult(
                null, null, "invalid_request", "<img src=x onerror=alert(1)>");

        String html = CallbackListener.errorPage(result);

        assertThat(html).contains("&lt;img src=x onerror=alert(1)&gt;");
        assertThat(html).doesNotContain("<img src=x onerror=alert(1)>");
    }

    @Test
    void errorPageEscapesAmpersandsAndQuotes() {
        CallbackResult result = new CallbackResult(
                null, null, "a&b\"c'd", "x&y\"z'w");

        String html = CallbackListener.errorPage(result);

        assertThat(html).contains("a&amp;b&quot;c&#39;d");
        assertThat(html).contains("x&amp;y&quot;z&#39;w");
        assertThat(html).doesNotContain("a&b\"c'd");
        assertThat(html).doesNotContain("x&y\"z'w");
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
