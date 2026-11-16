package com.mcpscanner.checks.catalog.sqlinjection;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;
import com.mcpscanner.mcp.TooManyRequests;

import java.util.List;

final class ProbeField {

    static final int UNANSWERED_PROBES_BEFORE_GIVING_UP = 2;

    private final HttpRequestResponse base;
    private final AuditInsertionPoint insertionPoint;
    private final Http http;
    private int consecutiveUnanswered;
    private boolean rateLimited;

    ProbeField(HttpRequestResponse base, AuditInsertionPoint insertionPoint, Http http) {
        this.base = base;
        this.insertionPoint = insertionPoint;
        this.http = http;
    }

    String described() {
        return SkipSubject.field(base, insertionPoint);
    }

    String original() {
        String value = insertionPoint.baseValue();
        return value == null ? "" : value;
    }

    Probe baseline() {
        HttpRequestResponse exchange = base.response() != null ? base : http.sendRequest(base.request());
        return new Probe(exchange, ReplyShape.of(exchange, List.of()));
    }

    Probe send(ValueSlot slot, String rewritten) {
        String value = slot.with(rewritten);
        HttpRequestResponse exchange = gaveUp() ? null : sent(value);
        return new Probe(exchange, ReplyShape.of(exchange, List.of(new Reflection(value, original()),
                new Reflection(rewritten, slot.segment()))));
    }

    boolean gaveUp() {
        return consecutiveUnanswered >= UNANSWERED_PROBES_BEFORE_GIVING_UP;
    }

    boolean unresponsive() {
        return !rateLimited && gaveUp();
    }

    private HttpRequestResponse sent(String value) {
        HttpRequestResponse exchange = http.sendRequest(
                insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(value)));
        consecutiveUnanswered = exchange == null || exchange.response() == null ? consecutiveUnanswered + 1 : 0;
        rateLimited |= TooManyRequests.answered(exchange);
        return PayloadHighlights.ofPayload(exchange, insertionPoint, value);
    }
}
