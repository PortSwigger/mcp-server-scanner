package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
import com.mcpscanner.checks.api.RateLimitedSends;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;

import com.mcpscanner.mcp.RateLimitStop;
import java.util.Arrays;
import java.util.List;

final class ProbeField {

    static final String MATCHED_CONTROL_SUFFIX = "mcp-control";
    static final int UNANSWERED_PROBES_BEFORE_GIVING_UP = 2;

    private final HttpRequestResponse base;
    private final AuditInsertionPoint insertionPoint;
    private final Http probes;
    private final Http confirmations;
    private final FieldSubject subject;
    private int consecutiveUnanswered;
    private boolean rateLimited;
    private boolean quotaSpent;

    ProbeField(HttpRequestResponse base, AuditInsertionPoint insertionPoint, String fieldName,
               RateLimitedSends sends) {
        this.base = base;
        this.insertionPoint = insertionPoint;
        this.probes = sends.probes();
        this.confirmations = sends.confirmations();
        this.subject = FieldSubject.of(base.request(), fieldName);
    }

    FieldSubject subject() {
        return subject;
    }

    String described() {
        return SkipSubject.field(base, insertionPoint);
    }

    String original() {
        String value = insertionPoint.baseValue();
        return value == null ? "" : value;
    }

    List<ShellBreakout> breakouts() {
        return Arrays.stream(ShellBreakout.values())
                .filter(breakout -> insertionPoint.type() != AuditInsertionPointType.HEADER || breakout.fitsOnOneLine())
                .toList();
    }

    InjectionReply baseline() {
        return InjectionReply.of(base.response() != null ? base : noted(probes.sendRequest(base.request())));
    }

    InjectionReply send(String payload) {
        return quotaSpent ? InjectionReply.of(null) : send(probes, payload);
    }

    InjectionReply confirm(String payload) {
        return send(confirmations, payload);
    }

    private InjectionReply send(Http http, String payload) {
        if (gaveUp()) {
            return InjectionReply.of(null);
        }
        HttpRequestResponse exchange = http.sendRequest(
                insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload)));
        consecutiveUnanswered = exchange == null || exchange.response() == null ? consecutiveUnanswered + 1 : 0;
        return InjectionReply.of(PayloadHighlights.ofPayload(noted(exchange), insertionPoint, payload));
    }

    private HttpRequestResponse noted(HttpRequestResponse exchange) {
        RateLimitStop.of(exchange).ifPresent(this::stoppedBy);
        return exchange;
    }

    private void stoppedBy(RateLimitStop stop) {
        rateLimited = true;
        quotaSpent |= stop == RateLimitStop.QUOTA_SPENT;
    }

    boolean gaveUp() {
        return consecutiveUnanswered >= UNANSWERED_PROBES_BEFORE_GIVING_UP;
    }

    boolean unresponsive() {
        return !rateLimited && gaveUp();
    }

    InjectionReply sendMatchedControl() {
        return confirm(original() + MATCHED_CONTROL_SUFFIX);
    }
}
