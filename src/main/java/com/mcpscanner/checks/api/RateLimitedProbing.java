package com.mcpscanner.checks.api;

import burp.api.montoya.http.Http;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;
import java.util.function.Function;

public final class RateLimitedProbing {

    private final CheckLog log;

    public RateLimitedProbing(CheckLog log) {
        this.log = log;
    }

    public List<AuditIssue> run(String subject, Http http, Function<RateLimitedSends, List<AuditIssue>> probing) {
        RateLimitTrip trip = new RateLimitTrip();
        List<AuditIssue> issues = probing.apply(WithholdingAfterRateLimit.over(http, trip));
        trip.reason().ifPresent(reason -> log.notRun(subject, reason));
        return issues;
    }
}
