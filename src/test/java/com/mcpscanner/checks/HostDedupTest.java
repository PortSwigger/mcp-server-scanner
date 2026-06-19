package com.mcpscanner.checks;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class HostDedupTest {

    @Test
    void tryClaim_first_call_returns_true_subsequent_calls_return_false() {
        HostDedup dedup = new HostDedup();
        HttpRequest request = stubRequest("example.test", 8080, false, List.of());

        assertThat(dedup.tryClaim(request)).isTrue();
        assertThat(dedup.tryClaim(request)).isFalse();
    }

    @Test
    void collapses_different_authorization_headers_to_one_claim() {
        HostDedup dedup = new HostDedup();
        HttpRequest tokenA = stubRequest("example.test", 8080, false,
                List.of(header("Authorization", "Bearer token-A")));
        HttpRequest tokenB = stubRequest("example.test", 8080, false,
                List.of(header("Authorization", "Bearer token-B")));

        assertThat(dedup.tryClaim(tokenA)).isTrue();
        assertThat(dedup.tryClaim(tokenB)).isFalse();
    }

    @Test
    void identityDiscriminator_treats_different_fingerprints_as_different_targets() {
        HostDedup dedup = new HostDedup();
        HttpRequest request = stubRequest("example.test", 8080, false, List.of());

        assertThat(dedup.tryClaim(request, "fingerprint-A")).isTrue();
        assertThat(dedup.tryClaim(request, "fingerprint-B")).isTrue();
        assertThat(dedup.tryClaim(request, "fingerprint-A")).isFalse();
    }

    @Test
    void identityDiscriminator_release_lets_same_fingerprint_re_probe() {
        HostDedup dedup = new HostDedup();
        HttpRequest request = stubRequest("example.test", 8080, false, List.of());

        assertThat(dedup.tryClaim(request, "fingerprint-A")).isTrue();
        dedup.releaseIfHttpLayerErrored(request, "fingerprint-A");

        assertThat(dedup.tryClaim(request, "fingerprint-A")).isTrue();
    }

    @Test
    void authFingerprint_normalises_identity_header_name_case() {
        HttpRequest lowercase = stubRequest("example.test", 8080, false,
                List.of(header("authorization", "Bearer token")));
        HttpRequest mixedCase = stubRequest("example.test", 8080, false,
                List.of(header("Authorization", "Bearer token")));

        assertThat(HostDedup.authFingerprint(lowercase))
                .isEqualTo(HostDedup.authFingerprint(mixedCase));
    }

    @Test
    void treats_different_hosts_as_different() {
        HostDedup dedup = new HostDedup();
        HttpRequest hostA = stubRequest("host-a.test", 8080, false, List.of());
        HttpRequest hostB = stubRequest("host-b.test", 8080, false, List.of());

        assertThat(dedup.tryClaim(hostA)).isTrue();
        assertThat(dedup.tryClaim(hostB)).isTrue();
    }

    @Test
    void treats_different_ports_as_different() {
        HostDedup dedup = new HostDedup();
        HttpRequest port8080 = stubRequest("example.test", 8080, false, List.of());
        HttpRequest port9090 = stubRequest("example.test", 9090, false, List.of());

        assertThat(dedup.tryClaim(port8080)).isTrue();
        assertThat(dedup.tryClaim(port9090)).isTrue();
    }

    @Test
    void treats_different_schemes_as_different() {
        HostDedup dedup = new HostDedup();
        HttpRequest http = stubRequest("example.test", 8080, false, List.of());
        HttpRequest https = stubRequest("example.test", 8080, true, List.of());

        assertThat(dedup.tryClaim(http)).isTrue();
        assertThat(dedup.tryClaim(https)).isTrue();
    }

    @Test
    void releasing_after_http_error_lets_subsequent_invocation_re_probe() {
        HostDedup dedup = new HostDedup();
        HttpRequest request = stubRequest("example.test", 8080, false, List.of());

        assertThat(dedup.tryClaim(request)).isTrue();
        dedup.releaseIfHttpLayerErrored(request);

        assertThat(dedup.tryClaim(request)).isTrue();
    }

    @Test
    void releasing_when_not_claimed_is_a_noop() {
        HostDedup dedup = new HostDedup();
        HttpRequest request = stubRequest("example.test", 8080, false, List.of());

        dedup.releaseIfHttpLayerErrored(request);

        assertThat(dedup.tryClaim(request)).isTrue();
    }

    @Test
    void concurrent_invocations_emit_exactly_one_claim() throws Exception {
        int threadCount = 10;
        HostDedup dedup = new HostDedup();
        HttpRequest request = stubRequest("example.test", 8080, false, List.of());

        AtomicInteger successfulClaims = new AtomicInteger();
        CountDownLatch startLatch = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threadCount; i++) {
            futures.add(pool.submit(() -> {
                startLatch.await();
                if (dedup.tryClaim(request)) {
                    successfulClaims.incrementAndGet();
                }
                return null;
            }));
        }

        startLatch.countDown();
        for (Future<?> future : futures) {
            future.get(5, TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertThat(pool.awaitTermination(5, TimeUnit.SECONDS)).isTrue();

        assertThat(successfulClaims).hasValue(1);
    }

    @Test
    void same_host_with_different_bearers_emits_exactly_one_claim_under_concurrency() throws Exception {
        int bearers = 5;
        int threadsPerBearer = 4;
        HostDedup dedup = new HostDedup();

        List<HttpRequest> perBearerRequests = new ArrayList<>();
        for (int i = 0; i < bearers; i++) {
            perBearerRequests.add(stubRequest("example.test", 8080, false,
                    List.of(header("Authorization", "Bearer token-" + i))));
        }

        AtomicInteger successfulClaims = new AtomicInteger();
        CountDownLatch startLatch = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(bearers * threadsPerBearer);
        List<Future<?>> futures = new ArrayList<>();
        for (HttpRequest request : perBearerRequests) {
            for (int t = 0; t < threadsPerBearer; t++) {
                futures.add(pool.submit(() -> {
                    startLatch.await();
                    if (dedup.tryClaim(request)) {
                        successfulClaims.incrementAndGet();
                    }
                    return null;
                }));
            }
        }

        startLatch.countDown();
        for (Future<?> future : futures) {
            future.get(5, TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertThat(pool.awaitTermination(5, TimeUnit.SECONDS)).isTrue();

        assertThat(successfulClaims).hasValue(1);
    }

    private static HttpRequest stubRequest(String host, int port, boolean secure, List<HttpHeader> headers) {
        HttpRequest request = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        lenient().when(request.httpService()).thenReturn(service);
        lenient().when(request.headers()).thenReturn(headers);
        lenient().when(service.host()).thenReturn(host);
        lenient().when(service.port()).thenReturn(port);
        lenient().when(service.secure()).thenReturn(secure);
        return request;
    }

    private static HttpHeader header(String name, String value) {
        HttpHeader header = mock(HttpHeader.class);
        lenient().when(header.name()).thenReturn(name);
        lenient().when(header.value()).thenReturn(value);
        return header;
    }
}
