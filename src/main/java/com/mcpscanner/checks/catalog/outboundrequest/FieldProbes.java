package com.mcpscanner.checks.catalog.outboundrequest;

import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.checks.shared.collaborator.CollaboratorWatch;
import com.mcpscanner.checks.shared.collaborator.PayloadSource;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

final class FieldProbes {

    private static final String PROBE_HOST = "probe.invalid";

    private final CollaboratorWatch watch;

    FieldProbes(CollaboratorWatch watch) {
        this.watch = watch;
    }

    List<SentProbe> send(AuditInsertionPoint point, Http http) {
        return watch.probing(payloads -> sendEveryForm(point, http, payloads));
    }

    private static List<SentProbe> sendEveryForm(AuditInsertionPoint point, Http http, PayloadSource payloads) {
        List<SentProbe> sent = new ArrayList<>();
        for (ProbeForm form : applicable(point)) {
            Optional<CollaboratorPayload> payload = payloads.newPayload();
            payload.ifPresent(host -> sent.add(send(point, http, form, host)));
        }
        return sent;
    }

    static List<ProbeForm> applicable(AuditInsertionPoint point) {
        return Arrays.stream(ProbeForm.values()).filter(form -> form.render(PROBE_HOST, point.baseValue()).isPresent())
                .toList();
    }

    private static SentProbe send(AuditInsertionPoint point, Http http, ProbeForm form, CollaboratorPayload host) {
        String payload = form.render(host.toString(), point.baseValue()).orElseThrow();
        HttpRequest probe = point.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
        return new SentProbe(form, payload, host, PayloadHighlights.ofPayload(exchange(http, probe), point, payload));
    }

    private static HttpRequestResponse exchange(Http http, HttpRequest probe) {
        try {
            return http.sendRequest(probe);
        } catch (RuntimeException failure) {
            return HttpRequestResponse.httpRequestResponse(probe, null);
        }
    }
}
