package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

final class DeliveryProbe {

    private final Authorizer authorizer;
    private final URI authorizationEndpoint;
    private final CallbackDeliveryOracle oracle = new CallbackDeliveryOracle();

    DeliveryProbe(Authorizer authorizer, URI authorizationEndpoint) {
        this.authorizer = authorizer;
        this.authorizationEndpoint = authorizationEndpoint;
    }

    URI authorizationEndpoint() {
        return authorizationEndpoint;
    }

    Optional<RedirectFinding> probe(OwnedClient client, DeliveryCase deliveryCase) {
        DeliveryObservation observation = observe(client, deliveryCase);
        if (!observation.delivery().delivered()) {
            return Optional.empty();
        }
        return Optional.of(new RedirectFinding(FindingKind.forDelivery(observation.delivery()), authorizationEndpoint,
                deliveryCase.describe(observation.delivery()), observation.exchanges()));
    }

    DeliveryObservation observe(OwnedClient client, DeliveryCase deliveryCase) {
        CallbackPair pair = new CallbackPair(client.callback(), deliveryCase.candidate());
        List<String> registered = client.registration().redirectUris();
        if (!pair.confirmedBy(registered)) {
            return DeliveryObservation.unconfirmed();
        }
        String state = UUID.randomUUID().toString();
        AuthorizationAttempt control = authorizer.authorize(client.clientId(), pair.registered(), state,
                deliveryCase.variant());
        AuthorizationAttempt probe = authorizer.authorize(client.clientId(), pair.candidate(), state,
                deliveryCase.variant());
        Delivery delivery = deliveryCase.normalisePath()
                ? oracle.classifyWithNormalisation(pair, registered, state, control.outcome(), probe.outcome())
                : oracle.classify(pair, state, control.outcome(), probe.outcome());
        return new DeliveryObservation(delivery, Optional.of(client.registration().evidence()), control.exchange(),
                probe.exchange());
    }
}
