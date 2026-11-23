package com.mcpscanner.access;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

import static com.mcpscanner.testutil.AwaitedFutures.doneWithin;
import static com.mcpscanner.testutil.Polling.within;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class InFlightLimitTest {

    private static final Duration WAIT = Duration.ofSeconds(5);

    private final ExecutorService pool = Executors.newCachedThreadPool();
    private final CountDownLatch release = new CountDownLatch(1);
    private final AtomicInteger inFlight = new AtomicInteger();
    private final AtomicInteger mostInFlight = new AtomicInteger();
    private final AtomicInteger sentToTheServer = new AtomicInteger();
    private final Semaphore slots = new Semaphore(2);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @AfterEach
    void stopPool() {
        pool.shutdownNow();
    }

    @Test
    void aSendBeyondTheLimitWaitsForAnEarlierOneToFinish() {
        Http limited = new InFlightLimit(heldUntilReleased(), slots);

        List<CompletableFuture<HttpRequestResponse>> sends = List.of(send(limited), send(limited), send(limited));
        within(WAIT).until(() -> inFlight.get() == 2 && slots.hasQueuedThreads());
        release.countDown();
        doneWithin(CompletableFuture.allOf(sends.toArray(CompletableFuture[]::new)), WAIT);

        assertThat(mostInFlight).hasValue(2);
        assertThat(sends).allSatisfy(sent -> assertThat(sent).isCompleted());
    }

    @Test
    void aSendInterruptedWhileWaitingForASlotStopsTheRun() {
        slots.drainPermits();
        Thread.currentThread().interrupt();

        assertThatThrownBy(() -> new InFlightLimit(heldUntilReleased(), slots).sendRequest(mock(HttpRequest.class)))
                .isInstanceOf(AccessRunStopped.class);
        assertThat(Thread.interrupted()).isTrue();
    }

    @Test
    void aSendQueuedBehindARateLimitedOneIsStoppedOnceItGetsItsSlot() {
        Semaphore oneSlot = new Semaphore(1);
        Http limited = new InFlightLimit(new TooManyRequestsStop(heldUntilReleased(429)), oneSlot);

        CompletableFuture<HttpRequestResponse> rateLimited = send(limited);
        within(WAIT).until(() -> inFlight.get() == 1);
        CompletableFuture<HttpRequestResponse> queued = send(limited);
        within(WAIT).until(oneSlot::hasQueuedThreads);
        release.countDown();
        doneWithin(CompletableFuture.allOf(rateLimited, queued).exceptionally(failure -> null), WAIT);

        assertThat(queued).isCompletedExceptionally();
        assertThatThrownBy(queued::join).hasCauseInstanceOf(AccessRunStopped.class);
        assertThat(mostInFlight).hasValue(1);
        assertThat(sentToTheServer).hasValue(1);
    }

    private CompletableFuture<HttpRequestResponse> send(Http limited) {
        return CompletableFuture.supplyAsync(() -> limited.sendRequest(mock(HttpRequest.class)), pool);
    }

    private Http heldUntilReleased() {
        return heldUntilReleased(200);
    }

    private Http heldUntilReleased(int status) {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            sentToTheServer.incrementAndGet();
            mostInFlight.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
            try {
                release.await();
                return answered(status);
            } finally {
                inFlight.decrementAndGet();
            }
        });
        return http;
    }

    private static HttpRequestResponse answered(int status) {
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) status);
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        when(exchange.response()).thenReturn(response);
        return exchange;
    }
}
