package com.mcpscanner.checks.catalog.ssrffilterbypass;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.HostKey;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

final class ReportedFields {

    private record Subject(HostKey host, String path, String field) {
    }

    private final Set<Subject> reported = ConcurrentHashMap.newKeySet();

    boolean contains(HttpRequest base, FetchField field) {
        return reported.contains(subject(base, field));
    }

    boolean add(HttpRequest base, FetchField field) {
        return reported.add(subject(base, field));
    }

    private static Subject subject(HttpRequest base, FetchField field) {
        return new Subject(HostKey.of(base.httpService()), base.pathWithoutQuery(), field.subject());
    }
}
