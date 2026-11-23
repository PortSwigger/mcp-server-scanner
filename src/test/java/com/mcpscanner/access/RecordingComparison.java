package com.mcpscanner.access;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.access.AccessComparison;
import com.mcpscanner.access.AccessComparisonRun;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.mockito.Mockito.mock;

public final class RecordingComparison implements AccessComparison {
    final List<HttpRequest> compared = new CopyOnWriteArrayList<>();
    final AtomicInteger inFlight = new AtomicInteger();
    final AtomicInteger mostInFlight = new AtomicInteger();
    final AtomicInteger begun = new AtomicInteger();
    final AtomicInteger closed = new AtomicInteger();
    final AtomicBoolean interrupted = new AtomicBoolean();
    final Map<String, Boolean> identitiesOffTheItemThread = new ConcurrentHashMap<>();
    private final CountDownLatch release = new CountDownLatch(1);
    private volatile boolean holding;
    private volatile boolean citeBase;
    private volatile HttpRequest probe;

    public List<HttpRequest> compared() {
        return List.copyOf(compared);
    }

    public void citeBaseAsEvidence() {
        citeBase = true;
    }

    public void holdEveryCompare() {
        holding = true;
    }

    public void release() {
        release.countDown();
    }

    public void sendDuringEveryCompare(HttpRequest request) {
        probe = request;
    }

    @Override
    public AccessComparisonRun begin(Http http) {
        begun.incrementAndGet();
        return new AccessComparisonRun() {
            @Override
            public List<AuditIssue> compare(HttpRequestResponse ownerExchange, Executor identities) {
                compared.add(ownerExchange.request());
                identitiesOffTheItemThread.put(ownerExchange.request().bodyToString(), offThisThread(identities));
                mostInFlight.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
                try {
                    awaitRelease();
                    if (probe != null) {
                        http.sendRequest(probe);
                    }
                    return List.of(citeBase ? issueCiting(ownerExchange) : mock(AuditIssue.class));
                } finally {
                    inFlight.decrementAndGet();
                }
            }

            @Override
            public void close() {
                closed.incrementAndGet();
            }
        };
    }

    private static boolean offThisThread(Executor identities) {
        Thread item = Thread.currentThread();
        return CompletableFuture.supplyAsync(() -> Thread.currentThread() != item, identities).join();
    }

    private void awaitRelease() {
        if (!holding) {
            return;
        }
        try {
            release.await();
        } catch (InterruptedException interruption) {
            interrupted.set(true);
            Thread.currentThread().interrupt();
        }
    }

    private static AuditIssue issueCiting(HttpRequestResponse base) {
        return AuditIssue.auditIssue("Cross identity", "Detail", "Fix", base.request().url(),
                AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM, "Background", "Fix background",
                AuditIssueSeverity.HIGH, List.of(base));
    }
}
