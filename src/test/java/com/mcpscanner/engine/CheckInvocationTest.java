package com.mcpscanner.engine;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.http.OutsideScanQueue;
import com.mcpscanner.http.ScanQueueBypass;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CheckInvocationTest {

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void theEngineHandsChecksAnHttpAlreadyOffBurpsScanQueueSoItsRequestCountersSeeEverySend() {
        Http engineHttp = mock(Http.class);
        Http unqueued = mock(Http.class);
        AtomicReference<Http> handed = new AtomicReference<>();
        ActiveScanCheck check = mock(ActiveScanCheck.class);
        when(check.doCheck(any(), any(), any())).thenAnswer(call -> {
            handed.set(call.getArgument(2, Http.class));
            return null;
        });
        CheckInvocation invocation = new CheckInvocation(new RegisteredCheck(check, ScanCheckType.PER_REQUEST,
                SkippedInvocations.UNREPORTED), mock(HttpRequestResponse.class), "tools/call",
                Optional.<AuditInsertionPoint>empty());

        invocation.run(engineHttp);
        OutsideScanQueue.send(ScanQueueBypass.through(unqueued).around(handed.get()), request());

        verify(engineHttp).sendRequest(any(HttpRequest.class));
        verify(unqueued, never()).sendRequest(any(HttpRequest.class));
    }

    private static HttpRequest request() {
        return HttpRequest.httpRequestFromUrl("https://as.example/register");
    }
}
