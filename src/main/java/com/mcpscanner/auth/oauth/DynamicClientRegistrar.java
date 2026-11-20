package com.mcpscanner.auth.oauth;

import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.logging.McpEventLog;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.client.ClientInformationResponse;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationRequest;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.mcpscanner.core.oauth.RegistrationMode;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;
import java.util.Set;

final class DynamicClientRegistrar {

    private final BurpHttpRequestSender sender;
    private final ClientIdentityProvider identityProvider;
    private final McpEventLog eventLog;

    DynamicClientRegistrar(BurpHttpRequestSender sender, ClientIdentityProvider identityProvider, McpEventLog eventLog) {
        this.sender = sender;
        this.identityProvider = identityProvider;
        this.eventLog = eventLog;
    }

    ClientRegistration register(URI registrationEndpoint, OAuthClientHints hints, LoopbackCallback callback) {
        if (registrationEndpoint == null) {
            eventLog.warn("DCR registration failed: authorization server does not advertise a registration endpoint");
            throw new DcrUnsupportedException("Authorization server does not advertise a registration endpoint");
        }
        ClientMetadata requested = clientMetadata(hints, callback);
        Registered registered = send(new ClientRegistrationRequest(registrationEndpoint, requested, null));
        eventLog.info("DCR registered new client_id=" + registered.client().getID().getValue());
        return toRegistration(registered, requested.getName());
    }

    private Registered send(ClientRegistrationRequest request) {
        HTTPResponse httpResponse = null;
        try {
            httpResponse = OAuthHttpTimeouts.apply(request.toHTTPRequest()).send(sender);
            ClientRegistrationResponse response = ClientRegistrationResponse.parse(httpResponse);
            if (!response.indicatesSuccess()) {
                String detail = "HTTP " + httpResponse.getStatusCode();
                eventLog.warn("DCR registration failed: " + detail);
                throw new DcrUnsupportedException("Dynamic client registration failed: " + detail);
            }
            return new Registered(((ClientInformationResponse) response).getClientInformation(),
                    httpResponse.getBody());
        } catch (IOException | ParseException e) {
            String detail = httpResponse == null ? "request failed"
                    : "invalid response (HTTP " + httpResponse.getStatusCode() + ")";
            eventLog.warn("DCR registration failed: " + detail);
            throw new OAuthException("Dynamic client registration error: " + detail);
        }
    }

    private static ClientRegistration toRegistration(Registered registration, String requestedName) {
        ClientInformation registered = registration.client();
        return new ClientRegistration(
                registered.getID().getValue(),
                registered.getSecret() != null ? registered.getSecret().getValue() : null,
                Optional.ofNullable(registered.getRegistrationAccessToken()).map(token -> token.getValue()),
                Optional.ofNullable(registered.getRegistrationURI()).map(URI::toString),
                RegistrationMode.DCR, Optional.ofNullable(registration.responseBody()),
                registeredName(registered, requestedName));
    }

    private static Optional<String> registeredName(ClientInformation registered, String requestedName) {
        return Optional.ofNullable(registered.getMetadata().getName()).or(() -> Optional.ofNullable(requestedName))
                .filter(name -> !name.isBlank());
    }

    private record Registered(ClientInformation client, String responseBody) {
    }

    private ClientMetadata clientMetadata(OAuthClientHints hints, LoopbackCallback callback) {
        ClientMetadata metadata = new ClientMetadata();
        metadata.setRedirectionURIs(Set.of(callback.uri()));
        metadata.setGrantTypes(Set.of(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN));
        metadata.setResponseTypes(Set.of(ResponseType.CODE));
        metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.NONE);
        ClientIdentityRegistration.applyTo(metadata, identityProvider.current());
        metadata.setCustomField("application_type", "native");
        if (!hints.scopes().isEmpty()) {
            metadata.setScope(new Scope(hints.scopes().toArray(String[]::new)));
        }
        return metadata;
    }
}
