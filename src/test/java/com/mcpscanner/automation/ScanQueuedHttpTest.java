package com.mcpscanner.automation;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.time.Duration;
import java.util.function.Consumer;

import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;

class ScanQueuedHttpTest {

    private static final Duration QUEUE_WAIT = Duration.ofSeconds(3);

    private final Http burp = mock(Http.class);
    @SuppressWarnings("unchecked")
    private final Consumer<Duration> pause = mock(Consumer.class);
    private final Http queued = new ScanQueuedHttp(burp, QUEUE_WAIT, pause);
    private HttpRequest request;

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
        request = HttpRequest.httpRequestFromUrl("http://127.0.0.1:9/");
    }

    @Test
    void waitsInTheQueueBeforeEveryFreshSend() {
        queued.sendRequest(request);

        InOrder order = inOrder(pause, burp);
        order.verify(pause).accept(QUEUE_WAIT);
        order.verify(burp).sendRequest(request);
    }

    @Test
    void waitsInTheQueueBeforeEverySendOnANamedConnection() {
        queued.sendRequest(request, HttpMode.HTTP_1, "kept-alive");

        InOrder order = inOrder(pause, burp);
        order.verify(pause).accept(QUEUE_WAIT);
        order.verify(burp).sendRequest(request, HttpMode.HTTP_1, "kept-alive");
    }
}
