package com.mcpscanner.checks.catalog.oauthconsentstructurereflection;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;

import java.util.ArrayList;
import java.util.List;

final class ConsentStructureExchanges {

    private ConsentStructureExchanges() {
    }

    static List<HttpRequestResponse> of(FieldReflection reflection, ConsentStructureEvidence evidence) {
        List<HttpRequestResponse> exchanges = new ArrayList<>();
        if (reflection.field() == ReflectedField.CLIENT_NAME) {
            exchanges.add(markerSent(evidence.client().evidence(), reflection));
        }
        exchanges.addAll(pageTrail(reflection, evidence.page()));
        if (reflection.field() == ReflectedField.STATE) {
            exchanges.add(evidence.control().finalExchange());
        }
        return exchanges;
    }

    private static List<HttpRequestResponse> pageTrail(FieldReflection reflection, AuthorizationPage page) {
        List<HttpRequestResponse> trail = new ArrayList<>(page.exchanges());
        if (reflection.field() == ReflectedField.STATE) {
            trail.set(0, markerSent(trail.get(0), reflection));
        }
        int last = trail.size() - 1;
        trail.set(last, PayloadHighlights.ofProof(trail.get(last), List.of(reflection.parsedName())));
        return trail;
    }

    private static HttpRequestResponse markerSent(HttpRequestResponse exchange, FieldReflection reflection) {
        return PayloadHighlights.ofRequestText(exchange, List.of(reflection.marker().token()));
    }
}
