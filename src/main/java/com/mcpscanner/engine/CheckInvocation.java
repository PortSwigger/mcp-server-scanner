package com.mcpscanner.engine;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import com.mcpscanner.http.ScanQueueBypass;

import java.util.Optional;

record CheckInvocation(RegisteredCheck registered, HttpRequestResponse base, String requestName,
                       Optional<AuditInsertionPoint> insertionPoint) {

    ActiveScanCheck check() {
        return registered.check();
    }

    AuditResult run(Http http) {
        return check().doCheck(base, insertionPoint.orElse(null), ScanQueueBypass.alreadyOffScanQueue(http));
    }

    String target() {
        return base.request().url();
    }

    Optional<String> field() {
        return insertionPoint.map(AuditInsertionPoint::name);
    }

    RunningInvocation running() {
        return new RunningInvocation(check().checkName(), requestName, field());
    }
}
