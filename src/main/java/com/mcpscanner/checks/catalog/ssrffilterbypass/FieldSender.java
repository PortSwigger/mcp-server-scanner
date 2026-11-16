package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;

final class FieldSender {

    private final AuditInsertionPoint point;
    private final Http http;

    FieldSender(AuditInsertionPoint point, Http http) {
        this.point = point;
        this.http = http;
    }

    SentUrl send(ProbeUrl url) {
        HttpRequest probe = point.buildHttpRequestWithPayload(ByteArray.byteArray(url.url()));
        return new SentUrl(url, PayloadHighlights.ofPayload(exchange(probe), point, url.url()));
    }

    private HttpRequestResponse exchange(HttpRequest probe) {
        try {
            return http.sendRequest(probe);
        } catch (RuntimeException failure) {
            return HttpRequestResponse.httpRequestResponse(probe, null);
        }
    }
}
