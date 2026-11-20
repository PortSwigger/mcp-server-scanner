package com.mcpscanner.checks.catalog.sqlinjection;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.api.RateLimitedSends;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;
import com.mcpscanner.mcp.RateLimitStop;

import java.util.List;

final class ProbeField {

    static final int UNANSWERED_PROBES_BEFORE_GIVING_UP = 2;

    private final HttpRequestResponse base;
    private final AuditInsertionPoint insertionPoint;
    private final RateLimitedSends sends;
    private int consecutiveUnanswered;
    private boolean rateLimited;
    private boolean quotaSpent;

    ProbeField(HttpRequestResponse base, AuditInsertionPoint insertionPoint, RateLimitedSends sends) {
        this.base = base;
        this.insertionPoint = insertionPoint;
        this.sends = sends;
    }

    String described() {
        return SkipSubject.field(base, insertionPoint);
    }

    String original() {
        String value = insertionPoint.baseValue();
        return value == null ? "" : value;
    }

    Probe baseline() {
        HttpRequestResponse exchange = base.response() != null ? base
                : noted(sends.probes().sendRequest(base.request()));
        return new Probe(exchange, ReplyShape.of(exchange, List.of()));
    }

    Probe send(ValueSlot slot, String rewritten) {
        return sent(slot, rewritten, probesHeld() ? null : sends.probes());
    }

    Probe confirm(ValueSlot slot, String rewritten) {
        return sent(slot, rewritten, gaveUp() ? null : sends.confirmations());
    }

    boolean gaveUp() {
        return consecutiveUnanswered >= UNANSWERED_PROBES_BEFORE_GIVING_UP;
    }

    boolean probesHeld() {
        return gaveUp() || quotaSpent;
    }

    boolean unresponsive() {
        return !rateLimited && gaveUp();
    }

    private Probe sent(ValueSlot slot, String rewritten, Http http) {
        String value = slot.with(rewritten);
        HttpRequestResponse exchange = http == null ? null : sent(value, http);
        return new Probe(exchange, ReplyShape.of(exchange, List.of(new Reflection(value, original()),
                new Reflection(rewritten, slot.segment()))));
    }

    private HttpRequestResponse sent(String value, Http http) {
        HttpRequestResponse exchange = http.sendRequest(
                insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(value)));
        consecutiveUnanswered = exchange == null || exchange.response() == null ? consecutiveUnanswered + 1 : 0;
        return PayloadHighlights.ofPayload(noted(exchange), insertionPoint, value);
    }

    private HttpRequestResponse noted(HttpRequestResponse exchange) {
        RateLimitStop.of(exchange).ifPresent(this::stoppedBy);
        return exchange;
    }

    private void stoppedBy(RateLimitStop stop) {
        rateLimited = true;
        quotaSpent |= stop == RateLimitStop.QUOTA_SPENT;
    }
}
