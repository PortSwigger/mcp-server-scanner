package com.mcpscanner.http;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.BurpEmptyResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.MutableClock;
import com.mcpscanner.testutil.RecordingRequestOptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ConnectionReusingHttpTest {

    private static final String MCP_URL = "https://mcp.example.com/mcp";

    private static final Duration IDLE_LIMIT = KeptAliveConnections.IDLE_LIMIT;
    private static final int MAX_CONNECTIONS = KeptAliveConnections.MAX_CONNECTIONS_PER_ORIGIN;
    private static final Duration SERVER_KEEP_ALIVE = Duration.ofSeconds(2);
    private static final Duration SCAN_QUEUE_WAIT = Duration.ofSeconds(5);

    private final Http delegate = mock(Http.class);
    private final MutableClock clock = new MutableClock(Instant.parse("2026-11-19T00:00:00Z"));
    private ConnectionReuse reuse;
    private Http http;
    private HttpRequestResponse http1Reply;
    private HttpRequestResponse http2Reply;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        http1Reply = answeredWith("HTTP/1.1");
        http2Reply = answeredWith("HTTP/2");
        reuse = new ConnectionReuse(request -> false, request -> false, clock);
        http = ConnectionReusingHttp.around(delegate, reuse);
    }

    @Test
    void sendsToAnUnknownOriginOnAFreshClosingConnection() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);

        http.sendRequest(request());

        assertThat(plainSends().get(0).headerValue("Connection")).isEqualTo("close");
    }

    @Test
    void reusesOneSharedHttp1ConnectionOnceTheOriginAnsweredHttp1() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString()))
                .thenReturn(http1Reply);

        http.sendRequest(request());
        http.sendRequest(request());

        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(delegate).sendRequest(sent.capture(), eq(HttpMode.HTTP_1), anyString());
        assertThat(sent.getValue().hasHeader("Connection")).isFalse();
    }

    @Test
    void keepsUsingAConnectionThatAnsweredWithinTheIdleLimit() {
        answerEveryReusedSend();

        http.sendRequest(request());
        http.sendRequest(request());
        clock.advance(IDLE_LIMIT.dividedBy(2));
        http.sendRequest(request());
        clock.advance(IDLE_LIMIT.dividedBy(2));
        http.sendRequest(request());

        assertThat(reusedConnectionIds()).hasSize(3).containsOnly(reusedConnectionIds().get(0));
    }

    @Test
    void neverSendsOnAConnectionIdleLongerThanServersKeepThemOpen() {
        answerEveryReusedSend();

        http.sendRequest(request());
        http.sendRequest(request());
        clock.advance(IDLE_LIMIT.plusMillis(1));
        http.sendRequest(request());
        http.sendRequest(request());

        List<String> ids = reusedConnectionIds();
        assertThat(ids.subList(1, 3)).doesNotContain(ids.get(0)).containsOnly(ids.get(1));
    }

    @Test
    void measuresIdlenessFromWhenTheLastReplyArrived() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenAnswer(invocation -> {
            clock.advance(IDLE_LIMIT.multipliedBy(3));
            return http1Reply;
        });

        http.sendRequest(request());
        http.sendRequest(request());
        http.sendRequest(request());

        assertThat(reusedConnectionIds()).hasSize(2).containsOnly(reusedConnectionIds().get(0));
    }

    @Test
    void opensNoMoreConnectionsToAnOriginThanTheCapAndClosesLaterSendsThatFindNoneFresh() {
        answerEveryReusedSend();
        http.sendRequest(request());

        for (int send = 0; send <= MAX_CONNECTIONS; send++) {
            http.sendRequest(request());
            clock.advance(IDLE_LIMIT.plusMillis(1));
        }

        assertThat(reusedConnectionIds()).hasSize(MAX_CONNECTIONS).doesNotHaveDuplicates();
        assertThat(plainSends()).extracting(sent -> sent.headerValue("Connection")).containsExactly("close", "close");
    }

    @Test
    void keepsReusingAFreshConnectionOnceTheCapIsReached() {
        answerEveryReusedSend();
        http.sendRequest(request());
        for (int send = 0; send < MAX_CONNECTIONS; send++) {
            clock.advance(IDLE_LIMIT.plusMillis(1));
            http.sendRequest(request());
        }

        http.sendRequest(request());

        List<String> ids = reusedConnectionIds();
        assertThat(ids).hasSize(MAX_CONNECTIONS + 1);
        assertThat(ids.get(MAX_CONNECTIONS)).isEqualTo(ids.get(MAX_CONNECTIONS - 1));
    }

    @Test
    void opensConnectionsAgainAfterADisconnect() {
        answerEveryReusedSend();
        http.sendRequest(request());
        for (int send = 0; send < MAX_CONNECTIONS; send++) {
            http.sendRequest(request());
            clock.advance(IDLE_LIMIT.plusMillis(1));
        }
        reuse.forgetOrigins();

        http.sendRequest(request());
        http.sendRequest(request());

        assertThat(reusedConnectionIds()).hasSize(MAX_CONNECTIONS + 1).doesNotHaveDuplicates();
    }

    @Test
    void givesEverySendInFlightItsOwnConnection() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        List<String> inFlight = new ArrayList<>();
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenAnswer(invocation -> {
            inFlight.add(invocation.getArgument(2));
            if (inFlight.size() == 1) {
                http.sendRequest(request());
            }
            return http1Reply;
        });

        http.sendRequest(request());
        http.sendRequest(request());

        assertThat(inFlight).hasSize(2).doesNotHaveDuplicates();
    }

    @Test
    void neverReturnsToAConnectionThatWentIdleWhileAnotherStayedBusy() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        List<String> sends = new ArrayList<>();
        boolean[] nestNext = {true};
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenAnswer(invocation -> {
            sends.add(invocation.getArgument(2));
            if (nestNext[0]) {
                nestNext[0] = false;
                http.sendRequest(request());
            }
            return http1Reply;
        });
        http.sendRequest(request());
        http.sendRequest(request());
        String outer = sends.get(0);
        String inner = sends.get(1);

        clock.advance(IDLE_LIMIT.multipliedBy(6).dividedBy(10));
        http.sendRequest(request());
        clock.advance(IDLE_LIMIT.multipliedBy(6).dividedBy(10));
        nestNext[0] = true;
        http.sendRequest(request());

        assertThat(sends.get(2)).isEqualTo(outer);
        assertThat(sends.subList(3, 5)).contains(outer).doesNotContain(inner);
    }

    @Test
    void neverReusesAConnectionIdFromBeforeADisconnect() {
        answerEveryReusedSend();

        http.sendRequest(request());
        http.sendRequest(request());
        reuse.forgetOrigins();
        http.sendRequest(request());
        http.sendRequest(request());

        assertThat(reusedConnectionIds()).hasSize(2).doesNotHaveDuplicates();
    }

    @Test
    void neverReusesAConnectionIdWhoseSendWasInFlightDuringADisconnect() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        boolean[] disconnectDuringNextSend = {true};
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenAnswer(invocation -> {
            if (disconnectDuringNextSend[0]) {
                disconnectDuringNextSend[0] = false;
                reuse.forgetOrigins();
            }
            return http1Reply;
        });

        http.sendRequest(request());
        http.sendRequest(request());
        http.sendRequest(request());
        http.sendRequest(request());

        assertThat(reusedConnectionIds()).hasSize(2).doesNotHaveDuplicates();
    }

    @Test
    void neverReturnsAConnectionWhoseSendThrew() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString()))
                .thenThrow(new IllegalStateException("Connection reset"));
        http.sendRequest(request());
        assertThatThrownBy(() -> http.sendRequest(request()));
        reuse.forgetOrigins();
        answerEveryReusedSend();

        http.sendRequest(request());
        http.sendRequest(request());

        assertThat(reusedConnectionIds()).hasSize(2).doesNotHaveDuplicates();
    }

    @Test
    void neverReusesOneOriginsConnectionIdForAnotherOrigin() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString()))
                .thenReturn(http1Reply);
        HttpRequest previous = HttpRequest.httpRequestFromUrl("http://localhost:8651/mcp");
        HttpRequest current = HttpRequest.httpRequestFromUrl("http://127.0.0.1:8652/mcp");

        http.sendRequest(previous);
        http.sendRequest(previous);
        http.sendRequest(current);
        http.sendRequest(current);

        ArgumentCaptor<String> connectionIds = ArgumentCaptor.forClass(String.class);
        verify(delegate, times(2)).sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), connectionIds.capture());
        assertThat(connectionIds.getAllValues()).doesNotHaveDuplicates();
    }

    @Test
    void answersAReadTakenFreshButSentAfterTheServerClosedItsIdleConnection() {
        Http queued = queuedBehindAScanQueue(request -> true);
        queued.sendRequest(request());
        queued.sendRequest(request());
        clock.advance(IDLE_LIMIT.dividedBy(2));

        HttpRequestResponse exchange = queued.sendRequest(request());

        assertThat(exchange).isSameAs(http1Reply);
        assertThat(plainSends()).extracting(sent -> sent.headerValue("Connection")).containsExactly("close", "close");
    }

    @Test
    void neverResendsAWriteTakenFreshButSentAfterTheServerClosedItsIdleConnection() {
        Http queued = queuedBehindAScanQueue(request -> false);
        queued.sendRequest(request());
        queued.sendRequest(request());
        clock.advance(IDLE_LIMIT.dividedBy(2));

        HttpRequestResponse exchange = queued.sendRequest(request());

        assertThat(EmptyResponse.is(exchange.response())).isTrue();
        assertThat(plainSends()).hasSize(1);
    }

    @Test
    void resendsAReadOnlyOnceWhenTheFreshConnectionIsUnansweredToo() {
        Http queued = queuedBehindAScanQueue(request -> true);
        queued.sendRequest(request());
        queued.sendRequest(request());
        clock.advance(IDLE_LIMIT.dividedBy(2));
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(null);

        assertThat(queued.sendRequest(request())).isNull();

        assertThat(plainSends()).hasSize(2);
    }

    @Test
    void keepsAutoModeWithoutOurConnectionCloseOnceTheOriginAnsweredHttp2() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http2Reply);

        http.sendRequest(request());
        http.sendRequest(request());

        assertThat(plainSends()).extracting(sent -> sent.hasHeader("Connection")).containsExactly(true, false);
        verify(delegate, never()).sendRequest(any(HttpRequest.class), any(HttpMode.class), anyString());
    }

    @Test
    void neverResendsAReusedRequestThatGotNoResponseAndClosesLaterSends() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenReturn(null);

        http.sendRequest(request());
        assertThat(http.sendRequest(request())).isNull();
        http.sendRequest(request());

        verify(delegate, times(1)).sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString());
        assertThat(plainSends()).extracting(sent -> sent.headerValue("Connection")).containsExactly("close", "close");
    }

    @Test
    void treatsAnEmptyReplyOnAReusedConnectionAsNoResponseAndClosesLaterSends() {
        HttpRequestResponse empty = HttpRequestResponse.httpRequestResponse(request(), BurpEmptyResponse.create());
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenReturn(empty);

        http.sendRequest(request());
        assertThat(http.sendRequest(request())).isSameAs(empty);
        http.sendRequest(request());

        verify(delegate, times(1)).sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString());
        assertThat(plainSends()).extracting(sent -> sent.headerValue("Connection")).containsExactly("close", "close");
    }

    @Test
    void learnsNothingFromAnEmptyReply() {
        HttpRequestResponse empty = HttpRequestResponse.httpRequestResponse(request(), BurpEmptyResponse.create());
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(empty);

        http.sendRequest(request());
        http.sendRequest(request());

        assertThat(plainSends()).hasSize(2);
    }

    @Test
    void closesLaterSendsWhenAReusedSendThrows() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString()))
                .thenThrow(new IllegalStateException("Connection reset"));

        http.sendRequest(request());
        assertThatThrownBy(() -> http.sendRequest(request())).hasMessage("Connection reset");
        http.sendRequest(request());

        verify(delegate, times(1)).sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString());
        assertThat(plainSends()).hasSize(2);
    }

    @Test
    void learnsNothingFromAnUnansweredSend() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(null);

        http.sendRequest(request());
        http.sendRequest(request());

        assertThat(plainSends()).hasSize(2);
    }

    @Test
    void forgetsEveryOriginOnDisconnect() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);

        http.sendRequest(request());
        reuse.forgetOrigins();
        http.sendRequest(request());

        assertThat(plainSends()).extracting(sent -> sent.headerValue("Connection")).containsExactly("close", "close");
    }

    @Test
    void remembersEachOriginSeparately() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);

        http.sendRequest(request());
        http.sendRequest(HttpRequest.httpRequestFromUrl("https://mcp.example.com:8443/mcp"));

        assertThat(plainSends()).hasSize(2);
    }

    @Test
    void neitherLearnsFromNorReusesARequestTheLocalProxyAnswers() {
        Http proxied = ConnectionReusingHttp.around(delegate, new ConnectionReuse(request -> true));
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);

        proxied.sendRequest(request());
        proxied.sendRequest(request());

        assertThat(plainSends()).extracting(sent -> sent.headerValue("Connection")).containsExactly("close", "close");
    }

    @Test
    void keepsAConnectionHeaderTheCallerChoseWhenReusing() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString()))
                .thenReturn(http1Reply);

        http.sendRequest(request());
        http.sendRequest(request().withHeader("Connection", "Upgrade"));

        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(delegate).sendRequest(sent.capture(), eq(HttpMode.HTTP_1), anyString());
        assertThat(sent.getValue().headerValue("Connection")).isEqualTo("Upgrade");
    }

    @Test
    void addsTheSharedConnectionToTheCallersRequestOptions() {
        ArgumentCaptor<RequestOptions> options = ArgumentCaptor.forClass(RequestOptions.class);
        when(delegate.sendRequest(any(HttpRequest.class), options.capture())).thenReturn(http1Reply);
        RequestOptions noRedirects = RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.NEVER);

        http.sendRequest(request(), noRedirects);
        http.sendRequest(request(), noRedirects);

        RecordingRequestOptions fresh = RecordingRequestOptions.recorded(options.getAllValues().get(0));
        RecordingRequestOptions reused = RecordingRequestOptions.recorded(options.getAllValues().get(1));
        assertThat(fresh.httpMode()).isEmpty();
        assertThat(reused.httpMode()).contains(HttpMode.HTTP_1);
        assertThat(reused.connectionId()).hasValueSatisfying(id -> assertThat(id).startsWith(ConnectionReuse.CONNECTION_ID));
        assertThat(reused.redirectionMode()).contains(RedirectionMode.NEVER);
    }

    @Test
    void keepsAnExplicitHttpModeOnAFreshClosingConnection() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        http.sendRequest(request());

        http.sendRequest(request(), HttpMode.HTTP_2);

        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(delegate).sendRequest(sent.capture(), eq(HttpMode.HTTP_2));
        assertThat(sent.getValue().headerValue("Connection")).isEqualTo("close");
    }

    @Test
    void sendsAnExplicitNamedConnectionUntouched() {
        HttpRequest keepAlive = request().withAddedHeader("Connection", "keep-alive");

        http.sendRequest(keepAlive, HttpMode.AUTO, "caller-connection");

        verify(delegate).sendRequest(keepAlive, HttpMode.AUTO, "caller-connection");
    }

    @Test
    void neverSendsAConnectionIdThroughTheScannersHttpThatWentThroughTheExtensionsHttp() {
        answerEveryReusedSend();
        Http scanDelegate = scanDelegateAnsweringEveryReusedSend();
        Http scan = ConnectionReusingHttp.aroundScanSends(scanDelegate, reuse);

        http.sendRequest(request());
        for (int send = 0; send < 4; send++) {
            http.sendRequest(request());
            scan.sendRequest(request());
        }

        assertThat(reusedConnectionIds(scanDelegate)).isNotEmpty().doesNotContainAnyElementsOf(reusedConnectionIds());
    }

    @Test
    void retiresAScanConnectionIdleLongerThanTheLimitWhileTheExtensionKeepsItsOwnConnectionsBusy() {
        answerEveryReusedSend();
        Http scanDelegate = scanDelegateAnsweringEveryReusedSend();
        Http scan = ConnectionReusingHttp.aroundScanSends(scanDelegate, reuse);

        http.sendRequest(request());
        scan.sendRequest(request());
        for (int send = 0; send < 6; send++) {
            clock.advance(IDLE_LIMIT.dividedBy(2));
            http.sendRequest(request());
        }
        scan.sendRequest(request());

        List<String> scanIds = reusedConnectionIds(scanDelegate);
        assertThat(scanIds).hasSize(2).doesNotHaveDuplicates();
    }

    @Test
    void capsTheConnectionsToAnOriginAcrossTheExtensionsAndTheScannersHttp() {
        answerEveryReusedSend();
        Http scanDelegate = scanDelegateAnsweringEveryReusedSend();
        Http scan = ConnectionReusingHttp.aroundScanSends(scanDelegate, reuse);
        http.sendRequest(request());

        for (int send = 0; send < MAX_CONNECTIONS; send++) {
            clock.advance(IDLE_LIMIT.plusMillis(1));
            http.sendRequest(request());
            scan.sendRequest(request());
        }

        assertThat(java.util.stream.Stream.concat(reusedConnectionIds().stream(),
                reusedConnectionIds(scanDelegate).stream()).distinct()).hasSize(MAX_CONNECTIONS);
    }

    @Test
    void leavesAScanHttpAlreadyOffTheScanQueueToTheExtensionsConnections() {
        Http offQueue = ScanQueueBypass.alreadyOffScanQueue(http);

        assertThat(ConnectionReusingHttp.aroundScanSends(offQueue, reuse)).isSameAs(offQueue);
    }

    @Test
    void wrapsOnlyOnce() {
        assertThat(ConnectionReusingHttp.around(http, ConnectionReuse.withoutLocalAnswers())).isSameAs(http);
    }

    private Http queuedBehindAScanQueue(Predicate<HttpRequest> resendable) {
        Map<String, Instant> lastReplyByConnection = new HashMap<>();
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenAnswer(invocation -> {
            clock.advance(SCAN_QUEUE_WAIT);
            Instant lastReply = lastReplyByConnection.put(invocation.getArgument(2), clock.instant());
            boolean closedByServer = lastReply != null
                    && Duration.between(lastReply, clock.instant()).compareTo(SERVER_KEEP_ALIVE) > 0;
            return closedByServer
                    ? HttpRequestResponse.httpRequestResponse(request(), BurpEmptyResponse.create())
                    : http1Reply;
        });
        return ConnectionReusingHttp.around(delegate, new ConnectionReuse(request -> false, resendable, clock));
    }

    private void answerEveryReusedSend() {
        when(delegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(delegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenReturn(http1Reply);
    }

    private Http scanDelegateAnsweringEveryReusedSend() {
        Http scanDelegate = mock(Http.class);
        when(scanDelegate.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(scanDelegate.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenReturn(http1Reply);
        return scanDelegate;
    }

    private static List<String> reusedConnectionIds(Http sender) {
        ArgumentCaptor<String> connectionIds = ArgumentCaptor.forClass(String.class);
        verify(sender, org.mockito.Mockito.atLeast(0))
                .sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), connectionIds.capture());
        return connectionIds.getAllValues();
    }

    private List<String> reusedConnectionIds() {
        ArgumentCaptor<String> connectionIds = ArgumentCaptor.forClass(String.class);
        verify(delegate, org.mockito.Mockito.atLeast(0))
                .sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), connectionIds.capture());
        return connectionIds.getAllValues();
    }

    private List<HttpRequest> plainSends() {
        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(delegate, org.mockito.Mockito.atLeast(0)).sendRequest(sent.capture());
        return sent.getAllValues();
    }

    private static HttpRequest request() {
        return HttpRequest.httpRequestFromUrl(MCP_URL);
    }

    private static HttpRequestResponse answeredWith(String httpVersion) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.httpVersion()).thenReturn(httpVersion);
        when(response.statusCode()).thenReturn((short) 200);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        when(exchange.response()).thenReturn(response);
        return exchange;
    }
}
