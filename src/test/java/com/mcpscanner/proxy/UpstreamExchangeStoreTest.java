package com.mcpscanner.proxy;

import com.mcpscanner.http.ExchangeLease;
import com.mcpscanner.http.ExchangeRetention;
import com.mcpscanner.logging.McpEventLog;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class UpstreamExchangeStoreTest {

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void storedExchangeIsReturnedForAProxiedResponseCarryingItsId() {
        UpstreamExchangeStore store = new UpstreamExchangeStore();
        String id = store.put(exchange("{\"jsonrpc\":\"2.0\",\"id\":101}", "{\"result\":{}}"));

        HttpRequestResponse upstream = store.upstreamOf(proxiedCarrying(id)).orElseThrow();

        assertThat(upstream.request().url()).isEqualTo("https://upstream.test/mcp");
        assertThat(upstream.request().method()).isEqualTo("POST");
        assertThat(upstream.request().headerValue("Authorization")).isEqualTo("Bearer secret");
        assertThat(upstream.request().bodyToString()).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":101}");
        assertThat(upstream.response().statusCode()).isEqualTo((short) 200);
        assertThat(upstream.response().headerValue("Mcp-Session-Id")).isEqualTo("upstream-session");
        assertThat(upstream.response().bodyToString()).isEqualTo("{\"result\":{}}");
    }

    @Test
    void evidenceResponseDropsFramingHeadersAndStatesItsOwnLength() {
        UpstreamExchangeStore store = new UpstreamExchangeStore();
        RecordedExchange chunked = new RecordedExchange(URI.create("https://upstream.test/mcp"), "POST", Map.of(),
                "{}", 200, Map.of("Transfer-Encoding", List.of("chunked"), "Content-Length", List.of("999")),
                "abc".getBytes(StandardCharsets.UTF_8));

        HttpResponse response = store.upstreamOf(proxiedCarrying(store.put(chunked))).orElseThrow().response();

        assertThat(response.headerValue("Transfer-Encoding")).isNull();
        assertThat(response.headerValue("Content-Length")).isEqualTo("3");
    }

    @Test
    void unknownIdMissingHeaderAndMissingResponseFindNothing() {
        UpstreamExchangeStore store = new UpstreamExchangeStore();
        store.put(exchange("{}", "{}"));

        assertThat(store.upstreamOf(proxiedCarrying("not-an-issued-id"))).isEmpty();
        assertThat(store.upstreamOf(proxied(HttpResponse.httpResponse("HTTP/1.1 200\r\n\r\n{}")))).isEmpty();
        assertThat(store.upstreamOf(proxied(null))).isEmpty();
    }

    @Test
    void oldestExchangeIsEvictedOnceTheEntryBoundIsReached() {
        UpstreamExchangeStore store = new UpstreamExchangeStore(2, Long.MAX_VALUE);
        String oldest = store.put(exchange("{}", "{}"));
        String middle = store.put(exchange("{}", "{}"));
        String newest = store.put(exchange("{}", "{}"));

        assertThat(store.upstreamOf(proxiedCarrying(oldest))).isEmpty();
        assertThat(store.upstreamOf(proxiedCarrying(middle))).isPresent();
        assertThat(store.upstreamOf(proxiedCarrying(newest))).isPresent();
    }

    @Test
    void oldestExchangesAreEvictedOnceTheBodyByteBoundIsExceeded() {
        UpstreamExchangeStore store = new UpstreamExchangeStore(100, 10);
        String oldest = store.put(exchange("123", "456"));
        String newest = store.put(exchange("123", "456"));

        assertThat(store.upstreamOf(proxiedCarrying(oldest))).isEmpty();
        assertThat(store.upstreamOf(proxiedCarrying(newest))).isPresent();
    }

    @Test
    void heldExchangesSurviveEvictionPastTheBoundAndAreEvictedOnceReleased() {
        UpstreamExchangeStore store = new UpstreamExchangeStore(2, Long.MAX_VALUE);
        String base = store.put(exchange("{}", "{}"));
        ExchangeLease lease = store.retaining();
        lease.hold(proxiedCarrying(base));

        IntStream.range(0, 10).forEach(i -> store.put(exchange("{}", "{}")));

        assertThat(store.upstreamOf(proxiedCarrying(base))).isPresent();
        lease.close();
        store.put(exchange("{}", "{}"));
        assertThat(store.upstreamOf(proxiedCarrying(base))).isEmpty();
    }

    @Test
    void retentionKeepsWhatTheLeaseHeldPastItsCloseUntilReleased() {
        UpstreamExchangeStore store = new UpstreamExchangeStore(2, Long.MAX_VALUE);
        String held = store.put(exchange("{}", "{}"));
        ExchangeLease lease = store.retaining();
        lease.hold(proxiedCarrying(held));
        ExchangeRetention retention = lease.retainBeyondClose();
        lease.close();

        IntStream.range(0, 10).forEach(i -> store.put(exchange("{}", "{}")));
        assertThat(store.upstreamOf(proxiedCarrying(held))).isPresent();

        retention.release();
        store.put(exchange("{}", "{}"));
        assertThat(store.upstreamOf(proxiedCarrying(held))).isEmpty();
    }

    @Test
    void retainedExchangesAreBoundedInCountSoTinyBodiesCannotPinTheWholeScan() {
        UpstreamExchangeStore store = new UpstreamExchangeStore(1_000, Long.MAX_VALUE, Long.MAX_VALUE, 10,
                McpEventLog.noop());
        for (int registration = 0; registration < 50; registration++) {
            ExchangeLease lease = store.retaining();
            for (int probe = 0; probe < 5; probe++) {
                lease.hold(proxiedCarrying(store.put(exchange("{}", ""))));
            }
            lease.retainBeyondClose();
            lease.close();
        }

        assertThat(store.retainedExchanges()).isLessThanOrEqualTo(10);
    }

    @Test
    void aSingleRetentionOverBudgetReleasesItselfAtOnceAndSaysSo() {
        List<String> warnings = new ArrayList<>();
        McpEventLog eventLog = org.mockito.Mockito.mock(McpEventLog.class);
        org.mockito.Mockito.doAnswer(call -> warnings.add(call.getArgument(0))).when(eventLog).warn(
                org.mockito.ArgumentMatchers.anyString());
        UpstreamExchangeStore store = new UpstreamExchangeStore(1_000, Long.MAX_VALUE, Long.MAX_VALUE, 3, eventLog);
        ExchangeLease lease = store.retaining();
        String id = null;
        for (int probe = 0; probe < 5; probe++) {
            id = store.put(exchange("{}", ""));
            lease.hold(proxiedCarrying(id));
        }

        lease.retainBeyondClose();
        lease.close();

        assertThat(store.retainedExchanges()).isZero();
        assertThat(warnings).singleElement().asString().contains("released at once");
    }

    @Test
    void retainedExchangesAreBoundedInBytesSoManyRegistrationsCannotPinTheWholeScan() {
        UpstreamExchangeStore store = new UpstreamExchangeStore(20, Long.MAX_VALUE, 100);
        String lastRetained = null;
        for (int registration = 0; registration < 50; registration++) {
            ExchangeLease lease = store.retaining();
            for (int probe = 0; probe < 5; probe++) {
                String id = store.put(exchange("{}", "x".repeat(8)));
                lease.hold(proxiedCarrying(id));
                lastRetained = id;
            }
            lease.retainBeyondClose();
            lease.close();
        }

        assertThat(store.retainedBytes()).isLessThanOrEqualTo(100);
        assertThat(store.upstreamOf(proxiedCarrying(lastRetained))).isPresent();
        assertThat(store.size()).isLessThanOrEqualTo(20);
    }

    @Test
    void releasingARetentionTwiceDoesNotReleaseAnotherHoldersExchange() {
        UpstreamExchangeStore store = new UpstreamExchangeStore(1, Long.MAX_VALUE);
        String id = store.put(exchange("{}", "{}"));
        ExchangeLease first = store.retaining();
        ExchangeLease second = store.retaining();
        first.hold(proxiedCarrying(id));
        second.hold(proxiedCarrying(id));
        ExchangeRetention retention = first.retainBeyondClose();
        first.close();
        retention.release();
        retention.release();
        store.put(exchange("{}", "{}"));

        assertThat(store.upstreamOf(proxiedCarrying(id))).isPresent();
    }

    @Test
    void holdingAMissingExchangeOrOneWithoutAReplyHoldsNothingAndDoesNotFail() {
        ExchangeLease lease = new UpstreamExchangeStore().retaining();

        lease.hold(null);
        lease.hold(proxied(null));
        lease.close();
    }

    @Test
    void anExchangeHeldByTwoLeasesStaysUntilBothAreReleased() {
        UpstreamExchangeStore store = new UpstreamExchangeStore(1, Long.MAX_VALUE);
        String id = store.put(exchange("{}", "{}"));
        ExchangeLease first = store.retaining();
        ExchangeLease second = store.retaining();
        first.hold(proxiedCarrying(id));
        second.hold(proxiedCarrying(id));
        store.put(exchange("{}", "{}"));

        first.close();
        assertThat(store.upstreamOf(proxiedCarrying(id))).isPresent();
        second.close();
        store.put(exchange("{}", "{}"));
        assertThat(store.upstreamOf(proxiedCarrying(id))).isEmpty();
    }

    @Test
    void anExchangeLargerThanTheWholeBudgetIsNotKept() {
        UpstreamExchangeStore store = new UpstreamExchangeStore(100, 4);

        assertThat(store.upstreamOf(proxiedCarrying(store.put(exchange("123", "456"))))).isEmpty();
    }

    @Test
    void defaultBoundsAreFourThousandExchangesAndThirtyTwoMebibytesOfBodies() {
        assertThat(UpstreamExchangeStore.MAX_EXCHANGES).isEqualTo(4_096);
        assertThat(UpstreamExchangeStore.MAX_BODY_BYTES).isEqualTo(32L * 1024 * 1024);
    }

    @Test
    void idsAreOpaqueUniqueHexStringsEvenUnderConcurrentPuts() throws Exception {
        UpstreamExchangeStore store = new UpstreamExchangeStore();
        Map<String, Boolean> ids = new ConcurrentHashMap<>();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        IntStream.range(0, 400).forEach(i -> pool.submit(() -> ids.put(store.put(exchange("{}", "{}")), true)));
        pool.shutdown();
        assertThat(pool.awaitTermination(10, TimeUnit.SECONDS)).isTrue();

        assertThat(ids).hasSize(400);
        assertThat(ids.keySet()).allMatch(id -> id.matches("[0-9a-f]{32}"));
        assertThat(ids.keySet()).allMatch(id -> store.upstreamOf(proxiedCarrying(id)).isPresent());
    }

    @Test
    void retainingWhileAnotherThreadIsReleasingTheOldestRetentionStillMakesProgress() throws Exception {
        UpstreamExchangeStore store = new UpstreamExchangeStore(1_000, Long.MAX_VALUE, Long.MAX_VALUE, 1,
                McpEventLog.noop());
        ExchangeRetention oldest = retentionOfOneExchange(store);
        AtomicReference<Thread> releaserThread = new AtomicReference<>();
        ExecutorService releaser = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable);
            thread.setDaemon(true);
            releaserThread.set(thread);
            return thread;
        });

        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            synchronized (store) {
                releaser.submit(oldest::release);
                waitUntilTheReleaserIsBlockedOnTheStoreLock(releaserThread.get(), store);
                retentionOfOneExchange(store);
            }
        });

        assertThat(store.retainedExchanges()).isEqualTo(1);
        releaser.shutdownNow();
    }

    private static void waitUntilTheReleaserIsBlockedOnTheStoreLock(Thread releaserThread,
                                                                    UpstreamExchangeStore store)
            throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!isBlockedOn(releaserThread, store)) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("the releaser was never blocked on the store lock");
            }
            Thread.sleep(5);
        }
    }

    private static boolean isBlockedOn(Thread thread, Object monitor) {
        ThreadInfo info = ManagementFactory.getThreadMXBean().getThreadInfo(thread.getId());
        return info != null && info.getThreadState() == Thread.State.BLOCKED && info.getLockInfo() != null
                && info.getLockInfo().getIdentityHashCode() == System.identityHashCode(monitor);
    }

    @Test
    void anExchangeHeldByTwoRetentionsCountsOnceTowardTheCountBound() {
        UpstreamExchangeStore store = new UpstreamExchangeStore(2, Long.MAX_VALUE, Long.MAX_VALUE, 2,
                McpEventLog.noop());
        String shared = store.put(exchange("{}", "{}"));
        String other = store.put(exchange("{}", "{}"));
        retain(store, shared, other);
        retain(store, shared);
        store.put(exchange("{}", "{}"));

        assertThat(store.retainedExchanges()).isEqualTo(2);
        assertThat(store.upstreamOf(proxiedCarrying(other))).isPresent();
    }

    private static void retain(UpstreamExchangeStore store, String... ids) {
        ExchangeLease lease = store.retaining();
        for (String id : ids) {
            lease.hold(proxiedCarrying(id));
        }
        lease.retainBeyondClose();
        lease.close();
    }

    private static ExchangeRetention retentionOfOneExchange(UpstreamExchangeStore store) {
        ExchangeLease lease = store.retaining();
        lease.hold(proxiedCarrying(store.put(exchange("{}", "{}"))));
        ExchangeRetention retention = lease.retainBeyondClose();
        lease.close();
        return retention;
    }

    private static RecordedExchange exchange(String requestBody, String responseBody) {
        return new RecordedExchange(URI.create("https://upstream.test/mcp"), "POST",
                Map.of("Authorization", List.of("Bearer secret")), requestBody, 200,
                Map.of("Mcp-Session-Id", List.of("upstream-session")), responseBody.getBytes(StandardCharsets.UTF_8));
    }

    private static HttpRequestResponse proxiedCarrying(String id) {
        return proxied(HttpResponse.httpResponse("HTTP/1.1 200\r\n" + ScannerSentinels.EXCHANGE_HEADER + ": " + id
                + "\r\n\r\n{}"));
    }

    private static HttpRequestResponse proxied(HttpResponse response) {
        return HttpRequestResponse.httpRequestResponse(HttpRequest.httpRequestFromUrl("http://127.0.0.1:1/mcp"),
                response);
    }
}
