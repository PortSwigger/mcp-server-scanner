package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.api.RateLimitedSends;

record FieldProbe(HttpRequestResponse base, AuditInsertionPoint point, FetchField field, RateLimitedSends sends,
                  String subject) {

    int targetPort() {
        return base.httpService().port();
    }

    FieldSender prober() {
        return new FieldSender(point, sends.probes());
    }

    FieldSender confirmer() {
        return new FieldSender(point, sends.confirmations());
    }
}
