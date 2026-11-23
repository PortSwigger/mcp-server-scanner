package com.mcpscanner.client;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.http.BurpMessages;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.ResendableRequests;
import com.mcpscanner.testutil.BurpEmptyResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingBurpRequest;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static com.mcpscanner.testutil.RecordingRequestOptions.recorded;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class BurpProtocolHttpTransportTest {

    private static final URI TARGET = URI.create("https://mcp.example.com/mcp");
    private static final Duration TIMEOUT = Duration.ofSeconds(12);
    private static final String TOOLS_LIST = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
    private static final String UNKNOWN_TOOL_CALL =
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_all\"}}";

    private final Http http = mock(Http.class);
    private RecordingBurpRequest recorder;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        recorder = new RecordingBurpRequest();
    }

    @Test
    void sendsWithoutFollowingRedirectsAndWithTheResponseTimeout() throws Exception {
        respondWith("HTTP/1.1 200 OK\r\n\r\n{}");

        transport().send(post("{}"), TIMEOUT);

        ArgumentCaptor<RequestOptions> options = ArgumentCaptor.forClass(RequestOptions.class);
        verify(http).sendRequest(any(HttpRequest.class), options.capture());
        assertThat(recorded(options.getValue()).redirectionMode()).contains(RedirectionMode.NEVER);
        assertThat(recorded(options.getValue()).responseTimeout()).contains(TIMEOUT);
    }

    @Test
    void mapsMethodUrlAndHeadersOntoTheBurpRequest() throws Exception {
        respondWith("HTTP/1.1 200 OK\r\n\r\n{}");
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("Mcp-Session-Id", "abc");

        transport().send(new ProtocolHttpRequest(TARGET, "POST", headers, "{}"), TIMEOUT);

        assertThat(recorder.startedUrl()).isEqualTo(TARGET.toString());
        assertThat(recorder.method()).isEqualTo("POST");
        assertThat(recorder.addedHeaders())
                .containsExactly("Content-Type: application/json", "Mcp-Session-Id: abc");
    }

    @Test
    void leavesTheConnectionHeaderToTheConnectionReusePolicy() throws Exception {
        respondWith("HTTP/1.1 200 OK\r\n\r\n{}");

        transport().send(new ProtocolHttpRequest(TARGET, "POST", Map.of("connection", "keep-alive"), "{}"), TIMEOUT);

        assertThat(recorder.addedHeaders()).isEmpty();
    }

    @Test
    void encodesNonAsciiRequestBodyAsUtf8Bytes() throws Exception {
        respondWith("HTTP/1.1 200 OK\r\n\r\n{}");
        String json = "{\"text\":\"café ☃ 🚀\"}";

        transport().send(post(json), TIMEOUT);

        assertThat(recorder.bodyBytes()).isEqualTo(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void sendsNoBodyWhenRequestHasNone() throws Exception {
        respondWith("HTTP/1.1 202 Accepted\r\n\r\n");

        transport().send(new ProtocolHttpRequest(TARGET, "DELETE", Map.of(), null), TIMEOUT);

        assertThat(recorder.method()).isEqualTo("DELETE");
        assertThat(recorder.bodyBytes()).isNull();
    }

    @Test
    void mapsStatusHeadersBodyAndRequestUri() throws Exception {
        String json = "{\"text\":\"café 🚀\"}";
        respondWith("HTTP/1.1 401 Unauthorized\r\n"
                + "Content-Type: application/json\r\n"
                + "mcp-session-id: xyz\r\n"
                + "\r\n" + json);

        ProtocolHttpResponse response = transport().send(post("{}"), TIMEOUT);

        assertThat(response.status()).isEqualTo(401);
        assertThat(response.firstHeader("Mcp-Session-Id")).contains("xyz");
        assertThat(response.firstHeader("content-type")).contains("application/json");
        assertThat(response.uri()).isEqualTo(TARGET);
        try (InputStream body = response.body()) {
            assertThat(new String(body.readAllBytes(), StandardCharsets.UTF_8)).isEqualTo(json);
        }
    }

    @Test
    void decodesBodyFromResponseBytesNotFromBurpsLatin1BodyString() throws Exception {
        String json = "{\"text\":\"caf\u00e9 \u2603 \ud83d\ude80\"}";
        byte[] raw = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + json)
                .getBytes(StandardCharsets.UTF_8);
        HttpResponse burpResponse = HttpResponse.httpResponse(ByteArray.byteArray(raw));
        assertThat(burpResponse.bodyToString())
                .isEqualTo(new String(json.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1))
                .isNotEqualTo(json);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(inv -> HttpRequestResponse.httpRequestResponse(inv.getArgument(0), burpResponse));

        ProtocolHttpResponse response = transport().send(post("{}"), TIMEOUT);

        assertThat(response.body().readAllBytes()).isEqualTo(json.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void keepsEveryValueOfRepeatedResponseHeaders() throws Exception {
        respondWith("HTTP/1.1 401 Unauthorized\r\n"
                + "WWW-Authenticate: Bearer realm=\"a\"\r\n"
                + "WWW-Authenticate: Basic realm=\"b\"\r\n"
                + "\r\n");

        ProtocolHttpResponse response = transport().send(post("{}"), TIMEOUT);

        assertThat(response.headerValues("www-authenticate"))
                .containsExactly("Bearer realm=\"a\"", "Basic realm=\"b\"");
    }

    @Test
    void exposesEmptyBodyAsEmptyStream() throws Exception {
        respondWith("HTTP/1.1 202 Accepted\r\n\r\n");

        ProtocolHttpResponse response = transport().send(post("{}"), TIMEOUT);

        assertThat(response.body().readAllBytes()).isEmpty();
    }

    @Test
    void removesChunkFramingBurpLeftInTheBody() throws Exception {
        respondWith("HTTP/1.1 200 OK\r\n"
                + "transfer-encoding: Chunked\r\n"
                + "\r\n"
                + "4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n");

        ProtocolHttpResponse response = transport().send(post("{}"), TIMEOUT);

        assertThat(new String(response.body().readAllBytes(), StandardCharsets.UTF_8)).isEqualTo("{\"a\":1}");
    }

    @Test
    void keepsChunkedBodyThatBurpAlreadyDecoded() throws Exception {
        respondWith("HTTP/1.1 200 OK\r\n"
                + "Transfer-Encoding: chunked\r\n"
                + "\r\n"
                + "{\"a\":1}");

        ProtocolHttpResponse response = transport().send(post("{}"), TIMEOUT);

        assertThat(new String(response.body().readAllBytes(), StandardCharsets.UTF_8)).isEqualTo("{\"a\":1}");
    }

    @Test
    void oversizedBodyFailsWithoutCopyingIt() {
        ByteArray oversized = mock(ByteArray.class);
        when(oversized.length()).thenReturn(BoundedBodyReader.MAX_RESPONSE_BYTES + 1);
        when(oversized.getBytes()).thenThrow(new AssertionError("Oversized body must not be copied"));
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) 200);
        when(response.body()).thenReturn(oversized);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(inv -> HttpRequestResponse.httpRequestResponse(inv.getArgument(0), response));

        assertThatThrownBy(() -> transport().send(post("{}"), TIMEOUT))
                .isInstanceOf(IOException.class)
                .hasMessage("Upstream response exceeded " + BoundedBodyReader.MAX_RESPONSE_BYTES + " bytes");
    }

    @Test
    void missingRequestResponseFailsNamingTargetAndTimeout() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenReturn(null);

        assertThatThrownBy(() -> transport().send(post("{}"), TIMEOUT))
                .isInstanceOf(IOException.class)
                .hasMessageContaining(TARGET.toString())
                .hasMessageContaining("12 s")
                .hasMessageContaining("TLS handshake");
    }

    @Test
    void subSecondTimeoutIsReportedInMilliseconds() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenReturn(null);

        assertThatThrownBy(() -> transport().send(post("{}"), Duration.ofMillis(300)))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("within 300 ms");
    }

    @Test
    void fractionalSecondTimeoutIsReportedInMilliseconds() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenReturn(null);

        assertThatThrownBy(() -> transport().send(post("{}"), Duration.ofMillis(1500)))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("within 1500 ms");
    }

    @Test
    void wholeSecondTimeoutIsReportedInSeconds() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenReturn(null);

        assertThatThrownBy(() -> transport().send(post("{}"), TIMEOUT))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("within 12 s");
    }

    @Test
    void missingResponseNamesAHeldOpenReplyStreamAsAPossibleCause() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenReturn(null);

        assertThatThrownBy(() -> transport().send(post("{}"), TIMEOUT))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("kept its reply stream open");
    }

    @Test
    void missingResponseSuggestsTurningOffBurpNetworkingForServersAwaitingAPingAnswer() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenReturn(null);

        assertThatThrownBy(() -> transport().send(post("{}"), TIMEOUT))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("waits for a ping answer")
                .hasMessageContaining("turn off \"" + BurpNetworkingSetting.NAME + "\"");
    }

    @Test
    void burpRefusingAStreamedReplyFailsWithTheStreamingErrorNamingTheSetting() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new IllegalStateException("Streaming response received"));

        assertThatThrownBy(() -> transport().send(post("{}"), TIMEOUT))
                .isInstanceOf(BurpStreamingResponseException.class)
                .hasMessageContaining(TARGET.toString())
                .hasMessageContaining("\"" + BurpNetworkingSetting.NAME + "\" is on");
    }

    @Test
    void otherBurpFailuresPassThroughUnchanged() {
        IllegalStateException failure = new IllegalStateException("Extension unloading");
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenThrow(failure);

        assertThatThrownBy(() -> transport().send(post("{}"), TIMEOUT)).isSameAs(failure);
    }

    @Test
    void missingResponseFailsNamingTargetAndTimeout() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(inv -> HttpRequestResponse.httpRequestResponse(inv.getArgument(0), null));

        assertThatThrownBy(() -> transport().send(post("{}"), TIMEOUT))
                .isInstanceOf(IOException.class)
                .hasMessageContaining(TARGET.toString())
                .hasMessageContaining("12 s");
    }

    @Test
    void emptyResponseFailsAsAConnectionClosedBeforeAnyReplyByte() {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(inv -> HttpRequestResponse.httpRequestResponse(inv.getArgument(0),
                        BurpEmptyResponse.create()));

        assertThatThrownBy(() -> transport().send(post("{}"), TIMEOUT))
                .isInstanceOf(ConnectionClosedBeforeReplyException.class)
                .hasMessageContaining(TARGET.toString());
    }

    @Test
    void emptyResponseArrivingAtTheTimeoutFailsAsNoResponseNotAsAClosedConnection() {
        AtomicLong now = new AtomicLong();
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenAnswer(inv -> {
            now.addAndGet(TIMEOUT.toNanos());
            return HttpRequestResponse.httpRequestResponse(inv.getArgument(0), BurpEmptyResponse.create());
        });
        BurpProtocolHttpTransport transport = new BurpProtocolHttpTransport(http,
                new BurpMessages(recorder::startFrom), now::get);

        assertThatThrownBy(() -> transport.send(post("{}"), TIMEOUT))
                .isInstanceOf(IOException.class)
                .isNotInstanceOf(ConnectionClosedBeforeReplyException.class)
                .hasMessageContaining("within 12 s");
    }

    @Test
    void readRequestAnsweredEmptyIsResentOnceOnTheStaleConnectionRule() throws Exception {
        answerEmptyThen("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}");

        ProtocolHttpResponse response = StaleConnectionResendingTransport.whenResendable(transport(),
                new ResendableRequests()).send(post(TOOLS_LIST), TIMEOUT);

        assertThat(response.status()).isEqualTo(200);
        verify(http, times(2)).sendRequest(any(HttpRequest.class), any(RequestOptions.class));
    }

    @Test
    void writeRequestAnsweredEmptyIsNeverResent() {
        answerEmptyThen("HTTP/1.1 200 OK\r\n\r\n{}");

        assertThatThrownBy(() -> StaleConnectionResendingTransport.whenResendable(transport(),
                new ResendableRequests()).send(post(UNKNOWN_TOOL_CALL), TIMEOUT))
                .isInstanceOf(ConnectionClosedBeforeReplyException.class);
        verify(http, times(1)).sendRequest(any(HttpRequest.class), any(RequestOptions.class));
    }

    private void answerEmptyThen(String rawResponse) {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(inv -> HttpRequestResponse.httpRequestResponse(inv.getArgument(0),
                        BurpEmptyResponse.create()))
                .thenAnswer(inv -> HttpRequestResponse.httpRequestResponse(inv.getArgument(0),
                        HttpResponse.httpResponse(rawResponse)));
    }

    @Test
    void interruptingTheCallerAbandonsABlockedBurpSendPromptly() throws Exception {
        AtomicBoolean burpCallStarted = new AtomicBoolean();
        CountDownLatch releaseBurp = new CountDownLatch(1);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenAnswer(inv -> {
            burpCallStarted.set(true);
            awaitIgnoringInterrupts(releaseBurp);
            return null;
        });
        CompletableFuture<Throwable> outcome = new CompletableFuture<>();
        Thread caller = new Thread(() -> outcome.complete(failureOf(() -> transport().send(post("{}"), TIMEOUT))));

        try {
            caller.start();
            await().atMost(5, SECONDS).pollInterval(10, MILLISECONDS).untilTrue(burpCallStarted);
            caller.interrupt();

            await().atMost(1, SECONDS).pollInterval(10, MILLISECONDS).until(outcome::isDone);
            assertThat(outcome.join()).isInstanceOf(InterruptedException.class);
        } finally {
            releaseBurp.countDown();
        }
    }

    @Test
    void sendsThroughBurpOnANamedDaemonThread() throws Exception {
        AtomicReference<Thread> burpThread = new AtomicReference<>();
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenAnswer(inv -> {
            burpThread.set(Thread.currentThread());
            return HttpRequestResponse.httpRequestResponse(inv.getArgument(0),
                    HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n{}"));
        });

        ProtocolHttpResponse response = transport().send(post("{}"), TIMEOUT);

        assertThat(response.status()).isEqualTo(200);
        assertThat(burpThread.get()).isNotSameAs(Thread.currentThread());
        assertThat(burpThread.get().getName()).startsWith("mcp-burp-http");
        assertThat(burpThread.get().isDaemon()).isTrue();
    }

    @Test
    void sendAfterCloseFailsFastWithoutReachingBurp() {
        BurpProtocolHttpTransport transport = transport();
        transport.close();

        assertThatThrownBy(() -> transport.send(post("{}"), TIMEOUT))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("closed");
        verifyNoInteractions(http);
    }

    @Test
    void closeLetsTheBurpSenderThreadTerminate() throws Exception {
        AtomicReference<Thread> burpThread = new AtomicReference<>();
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenAnswer(inv -> {
            burpThread.set(Thread.currentThread());
            return HttpRequestResponse.httpRequestResponse(inv.getArgument(0),
                    HttpResponse.httpResponse("HTTP/1.1 200 OK\r\n\r\n{}"));
        });
        BurpProtocolHttpTransport transport = transport();
        transport.send(post("{}"), TIMEOUT);

        transport.close();

        await().atMost(5, SECONDS).pollInterval(10, MILLISECONDS)
                .untilAsserted(() -> assertThat(burpThread.get().isAlive()).isFalse());
    }

    @Test
    void closeInterruptsABlockedBurpSend() throws Exception {
        AtomicBoolean burpCallStarted = new AtomicBoolean();
        AtomicBoolean burpSendInterrupted = new AtomicBoolean();
        blockBurpSendUntilInterrupted(burpCallStarted, burpSendInterrupted);
        BurpProtocolHttpTransport transport = transport();
        sendOnDaemonThread(transport);
        await().atMost(5, SECONDS).pollInterval(10, MILLISECONDS).untilTrue(burpCallStarted);

        transport.close();

        await().atMost(5, SECONDS).pollInterval(10, MILLISECONDS).untilTrue(burpSendInterrupted);
    }

    @Test
    void interruptingTheCallerInterruptsTheBlockedBurpSend() throws Exception {
        AtomicBoolean burpCallStarted = new AtomicBoolean();
        AtomicBoolean burpSendInterrupted = new AtomicBoolean();
        blockBurpSendUntilInterrupted(burpCallStarted, burpSendInterrupted);
        Thread caller = sendOnDaemonThread(transport());
        await().atMost(5, SECONDS).pollInterval(10, MILLISECONDS).untilTrue(burpCallStarted);

        caller.interrupt();

        await().atMost(5, SECONDS).pollInterval(10, MILLISECONDS).untilTrue(burpSendInterrupted);
    }

    private void blockBurpSendUntilInterrupted(AtomicBoolean burpCallStarted, AtomicBoolean burpSendInterrupted) {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenAnswer(inv -> {
            burpCallStarted.set(true);
            try {
                new CountDownLatch(1).await();
            } catch (InterruptedException expected) {
                burpSendInterrupted.set(true);
            }
            return null;
        });
    }

    private static Thread sendOnDaemonThread(BurpProtocolHttpTransport transport) {
        Thread caller = new Thread(() -> failureOf(() -> transport.send(post("{}"), TIMEOUT)));
        caller.setDaemon(true);
        caller.start();
        return caller;
    }

    @Test
    void propagatesRuntimeExceptionFromBurpUnchanged() {
        IllegalStateException burpFailure = new IllegalStateException("Burp rejected the request");
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenThrow(burpFailure);

        assertThatThrownBy(() -> transport().send(post("{}"), TIMEOUT)).isSameAs(burpFailure);
    }

    @Test
    void propagatesErrorFromBurpUnchanged() {
        OutOfMemoryError burpFailure = new OutOfMemoryError("Burp ran out of memory");
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenThrow(burpFailure);

        assertThatThrownBy(() -> transport().send(post("{}"), TIMEOUT)).isSameAs(burpFailure);
    }

    private static void awaitIgnoringInterrupts(CountDownLatch latch) {
        while (true) {
            try {
                latch.await();
                return;
            } catch (InterruptedException ignoredLikeMontoyaDoes) {
            }
        }
    }

    private static Throwable failureOf(ThrowingCallable call) {
        try {
            call.call();
            return null;
        } catch (Throwable failure) {
            return failure;
        }
    }

    @Test
    void attachesBurpsOwnExchangeAsTheWireRecord() throws Exception {
        String raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n"
                + "2\r\n{}\r\n0\r\n\r\n";
        HttpRequest[] sentByBurp = new HttpRequest[1];
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class))).thenAnswer(inv -> {
            sentByBurp[0] = inv.getArgument(0);
            return HttpRequestResponse.httpRequestResponse(sentByBurp[0], HttpResponse.httpResponse(raw));
        });

        ProtocolHttpResponse response = transport().send(post("{}"), TIMEOUT);

        HttpRequestResponse evidence = response.wire().orElseThrow().evidence();
        assertThat(evidence.request().toByteArray().getBytes()).isEqualTo(sentByBurp[0].toByteArray().getBytes());
        assertThat(new String(evidence.response().toByteArray().getBytes(), StandardCharsets.ISO_8859_1))
                .isEqualTo(raw);
    }

    private void respondWith(String rawResponse) {
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(inv -> HttpRequestResponse.httpRequestResponse(
                        inv.getArgument(0), HttpResponse.httpResponse(rawResponse)));
    }

    private BurpProtocolHttpTransport transport() {
        return new BurpProtocolHttpTransport(http, new BurpMessages(recorder::startFrom));
    }

    private static ProtocolHttpRequest post(String body) {
        return new ProtocolHttpRequest(TARGET, "POST", Map.of("Content-Type", "application/json"), body);
    }
}
