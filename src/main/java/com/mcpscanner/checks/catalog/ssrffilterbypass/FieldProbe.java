package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

record FieldProbe(HttpRequestResponse base, AuditInsertionPoint point, FetchField field, Http http, String subject) {

    int targetPort() {
        return base.httpService().port();
    }
}
