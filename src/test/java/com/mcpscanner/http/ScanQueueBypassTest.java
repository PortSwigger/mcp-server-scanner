package com.mcpscanner.http;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScanQueueBypassTest {

    private final Http scan = mock(Http.class);
    private final Http unqueued = mock(Http.class);
    private final HttpRequestResponse scanReply = mock(HttpRequestResponse.class);
    private final HttpRequestResponse unqueuedReply = mock(HttpRequestResponse.class);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        when(scan.sendRequest(any(HttpRequest.class))).thenReturn(scanReply);
        when(unqueued.sendRequest(any(HttpRequest.class))).thenReturn(unqueuedReply);
    }

    @Test
    void anOrdinarySendStaysOnTheScanQueue() {
        Http routed = ScanQueueBypass.through(unqueued).around(scan);

        assertThat(routed.sendRequest(request())).isSameAs(scanReply);
        verify(unqueued, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void aSendMarkedOutsideTheScanQueueGoesToTheUnqueuedHttp() {
        Http routed = ScanQueueBypass.through(unqueued).around(scan);

        assertThat(OutsideScanQueue.send(routed, request())).isSameAs(unqueuedReply);
        verify(scan, never()).sendRequest(any(HttpRequest.class));
    }

    @Test
    void theMarkReachesTheRouterThroughWrappersAboveIt() {
        RequestTally tally = RequestTally.started();
        Http wrapped = CountingHttp.counting(ScanQueueBypass.through(unqueued).around(scan), tally);

        assertThat(OutsideScanQueue.send(wrapped, request())).isSameAs(unqueuedReply);
        assertThat(tally.requests()).isEqualTo(1);
    }

    @Test
    void everySingleSendOverloadHonoursTheMark() {
        Http routed = ScanQueueBypass.through(unqueued).around(scan);
        RequestOptions options = mock(RequestOptions.class);

        OutsideScanQueue.send(routed, request());
        markedSend(() -> routed.sendRequest(request(), HttpMode.AUTO));
        markedSend(() -> routed.sendRequest(request(), HttpMode.AUTO, "id"));
        markedSend(() -> routed.sendRequest(request(), options));

        verify(unqueued).sendRequest(any(HttpRequest.class), any(HttpMode.class));
        verify(unqueued).sendRequest(any(HttpRequest.class), any(HttpMode.class), any(String.class));
        verify(unqueued).sendRequest(any(HttpRequest.class), any(RequestOptions.class));
        verify(scan, never()).sendRequest(any(HttpRequest.class), any(HttpMode.class));
    }

    @Test
    void theMarkEndsWithItsSendEvenWhenTheSendFails() {
        Http failing = mock(Http.class);
        when(failing.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException("down"));
        Http routed = ScanQueueBypass.through(failing).around(scan);

        assertThatThrownBy(() -> OutsideScanQueue.send(routed, request())).isInstanceOf(IllegalStateException.class);

        assertThat(routed.sendRequest(request())).isSameAs(scanReply);
    }

    @Test
    void withoutABypassAMarkedSendStaysOnTheScanHttp() {
        Http routed = ScanQueueBypass.NONE.around(scan);

        assertThat(routed).isSameAs(scan);
        assertThat(OutsideScanQueue.send(routed, request())).isSameAs(scanReply);
    }

    @Test
    void anHttpAlreadyOffTheScanQueueKeepsItsMarkedSendsSoItsOwnWrappersSeeThem() {
        Http routed = ScanQueueBypass.through(unqueued).around(ScanQueueBypass.alreadyOffScanQueue(scan));

        assertThat(OutsideScanQueue.send(routed, request())).isSameAs(scanReply);
        verify(unqueued, never()).sendRequest(any(HttpRequest.class));
    }

    private static void markedSend(Runnable send) {
        Http marker = mock(Http.class);
        when(marker.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            send.run();
            return null;
        });
        OutsideScanQueue.send(marker, request());
    }

    private static HttpRequest request() {
        return HttpRequest.httpRequestFromUrl("https://as.example/register");
    }
}
