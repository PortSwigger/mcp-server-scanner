package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

record DeliveryObservation(Delivery delivery, Optional<HttpRequestResponse> registration,
                           Optional<HttpRequestResponse> control, Optional<HttpRequestResponse> probe) {

    static DeliveryObservation unconfirmed() {
        return new DeliveryObservation(Delivery.INCONCLUSIVE, Optional.empty(), Optional.empty(), Optional.empty());
    }

    List<HttpRequestResponse> exchanges() {
        return Stream.of(registration, control, probe).flatMap(Optional::stream).toList();
    }
}
