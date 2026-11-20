package com.mcpscanner.auth.oauth;

import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.logging.McpEventLog;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.mcpscanner.core.oauth.AuthorizationServerCapabilities;
import com.mcpscanner.core.oauth.CimdDocumentValidator;
import com.mcpscanner.core.oauth.RegisteredClient;
import com.mcpscanner.core.oauth.RegistrationException;
import com.mcpscanner.core.oauth.RegistrationMode;
import com.mcpscanner.core.oauth.RegistrationRequest;
import com.mcpscanner.core.oauth.RegistrationSelection;
import com.mcpscanner.core.oauth.RegistrationSelector;

import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.Optional;

final class ClientRegistrar {

    private static final String PURPOSE_CLIENT_METADATA_DOCUMENT = "OAuth client metadata document";
    private static final String CLIENT_NAME = "client_name";

    private final BurpHttpRequestSender sender;
    private final OAuthDestinationGuard guard;
    private final DynamicClientRegistrar dynamicRegistrar;
    private final McpEventLog eventLog;

    ClientRegistrar(BurpHttpRequestSender sender, OAuthDestinationGuard guard,
                    ClientIdentityProvider identityProvider, McpEventLog eventLog) {
        this.sender = sender;
        this.guard = guard;
        this.dynamicRegistrar = new DynamicClientRegistrar(sender, identityProvider, eventLog);
        this.eventLog = eventLog;
    }

    ClientRegistration register(AuthorizationServerMetadata metadata, OAuthClientHints hints,
                                LoopbackCallback callback, URI mcpResource) {
        RegistrationSelection selection = select(metadata, hints, callback);
        if (selection.mode() == RegistrationMode.DCR) {
            return dynamicRegistrar.register(metadata.getRegistrationEndpointURI(), hints, callback);
        }
        Optional<String> clientName = selection.mode() == RegistrationMode.CIMD
                ? Optional.of(validClientDocumentName(hints, callback, mcpResource))
                : Optional.empty();
        eventLog.info("DCR skipped - registration mode=" + selection.mode());
        return new ClientRegistration(selection.clientId(), selection.clientSecret(), selection.mode(), clientName);
    }

    private static RegistrationSelection select(AuthorizationServerMetadata metadata, OAuthClientHints hints,
                                                LoopbackCallback callback) {
        RegisteredClient configured = hints.clientId() != null
                ? new RegisteredClient(hints.issuer(), hints.clientId(), hints.clientSecret()) : null;
        AuthorizationServerCapabilities capabilities = new AuthorizationServerCapabilities(
                Boolean.TRUE.equals(metadata.getCustomParameter("client_id_metadata_document_supported")),
                hints.allowDcr() ? metadata.getRegistrationEndpointURI() : null);
        try {
            return new RegistrationSelector().select(new RegistrationRequest(
                    URI.create(metadata.getIssuer().getValue()), configured, hints.clientMetadataUrl(),
                    capabilities, callback.uri(), hints.registrationMode()));
        } catch (RegistrationException e) {
            throw new OAuthException(e.getMessage(), e);
        }
    }

    private String validClientDocumentName(OAuthClientHints hints, LoopbackCallback callback, URI mcpResource) {
        if (hints.redirectPort() == 0) {
            throw new OAuthException("CIMD requires a configured fixed callback port");
        }
        URI location = hints.clientMetadataUrl();
        guard.requireAllowed(location, PURPOSE_CLIENT_METADATA_DOCUMENT, mcpResource);
        try {
            HTTPResponse response = OAuthHttpTimeouts.apply(new HTTPRequest(HTTPRequest.Method.GET, location)).send(sender);
            response.ensureStatusCode(200);
            Map<String, Object> document = JSONObjectUtils.parse(response.getBody());
            new CimdDocumentValidator().validate(location, document, callback.uri());
            return (String) document.get(CLIENT_NAME);
        } catch (IOException | GeneralException e) {
            throw new OAuthException("Failed to fetch client metadata document: " + e.getMessage(), e);
        } catch (RegistrationException invalidDocument) {
            throw new OAuthException(invalidDocument.getMessage(), invalidDocument);
        }
    }
}
