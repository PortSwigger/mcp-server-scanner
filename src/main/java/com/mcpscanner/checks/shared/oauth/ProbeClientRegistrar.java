package com.mcpscanner.checks.shared.oauth;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

public final class ProbeClientRegistrar {

    private static final Set<Integer> EXPLICIT_REJECTIONS = Set.of(400, 422);

    private final OAuthHttp http;
    private final ClientDeleter deleter;
    private final URI registrationEndpoint;
    private static final String INVALID_CLIENT_METADATA = "invalid_client_metadata";

    private final List<RegisteredClient> registered = new CopyOnWriteArrayList<>();

    public ProbeClientRegistrar(OAuthHttp http, URI registrationEndpoint) {
        this.http = http;
        this.deleter = new ClientDeleter(http);
        this.registrationEndpoint = registrationEndpoint;
    }

    public URI endpoint() {
        return registrationEndpoint;
    }

    public Registration register(ClientMetadata metadata) {
        Optional<HttpRequestResponse> exchange = http.postJson(registrationEndpoint, metadata.toJson());
        if (exchange.isEmpty()) {
            return Registration.inconclusive(exchange);
        }
        HttpRequestResponse response = exchange.get();
        if (EXPLICIT_REJECTIONS.contains((int) response.response().statusCode())) {
            return Registration.rejected(response);
        }
        Registration registration = JsonDocument.fromSuccessfulResponse(response)
                .flatMap(document -> document.text("client_id")
                        .map(clientId -> new RegisteredClient(clientId, document.texts("redirect_uris"), response,
                                ClientManagement.from(document, registrationEndpoint),
                                ClientSecret.issuedIn(document))))
                .map(Registration::accepted)
                .orElseGet(() -> Registration.inconclusive(exchange));
        registration.client().ifPresent(registered::add);
        return registration;
    }

    public Registration registerAddingRefreshGrantIfRequired(ClientMetadata metadata) {
        Registration registration = register(metadata);
        return rejectsClientMetadata(registration) ? register(metadata.withRefreshGrant()) : registration;
    }

    public ClientCleanup deleteRegisteredClients() {
        int deleted = 0;
        for (RegisteredClient client : registered) {
            if (client.management().map(deleter::delete).orElse(false)) {
                deleted++;
            }
        }
        ClientCleanup cleanup = new ClientCleanup(registered.size(), deleted);
        registered.clear();
        return cleanup;
    }

    private static boolean rejectsClientMetadata(Registration registration) {
        return registration.status() == RegistrationStatus.REJECTED && registration.exchange()
                .flatMap(exchange -> JsonDocument.parse(exchange.response().bodyToString()))
                .flatMap(document -> document.text("error"))
                .filter(INVALID_CLIENT_METADATA::equals)
                .isPresent();
    }
}
