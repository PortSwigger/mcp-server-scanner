package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class WildcardHostProbe implements RedirectProbe {

    private static final String MATCHED_SHAPE = "concrete host matched only by the registered wildcard";
    private static final String UNMATCHED_SHAPE = "URI outside the registered wildcard";

    @Override
    public List<RedirectFinding> run(ProbeContext context) {
        if (context.clients().https().isEmpty()) {
            return List.of();
        }
        URI control = CallbackUris.httpsControl();
        CallbackUris.WildcardCallback wildcard = CallbackUris.wildcard();
        List<String> redirectUris = List.of(control.toString(), wildcard.pattern());
        return context.registrar().register(ProbeClientMetadata.redirectingTo(redirectUris))
                .clientListingAll(redirectUris)
                .flatMap(client -> expansion(context, new OwnedClient(client, control), wildcard))
                .stream()
                .toList();
    }

    private static Optional<RedirectFinding> expansion(ProbeContext context, OwnedClient client,
                                                       CallbackUris.WildcardCallback wildcard) {
        DeliveryObservation matched = context.delivery().observe(client,
                DeliveryCase.of(MATCHED_SHAPE, wildcard.matchingHost(), AuthorizationVariant.STANDARD));
        if (matched.delivery() != Delivery.CODE) {
            return Optional.empty();
        }
        List<HttpRequestResponse> evidence = new ArrayList<>(matched.exchanges());
        for (URI outside : List.of(wildcard.unmatchedHost(), wildcard.unmatchedPath())) {
            DeliveryObservation unmatched = context.delivery().observe(client,
                    DeliveryCase.of(UNMATCHED_SHAPE, outside, AuthorizationVariant.STANDARD));
            if (unmatched.delivery() != Delivery.REJECTED) {
                return Optional.empty();
            }
            unmatched.probe().ifPresent(evidence::add);
        }
        return Optional.of(new RedirectFinding(FindingKind.WILDCARD_EXPANSION, context.delivery().authorizationEndpoint(),
                "authorization code delivered to " + wildcard.matchingHost() + " (matched only by "
                        + wildcard.pattern() + "), while " + wildcard.unmatchedHost() + " and "
                        + wildcard.unmatchedPath() + " were rejected",
                evidence));
    }
}
