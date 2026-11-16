package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.core.protocol.ClientProfile;
import com.mcpscanner.core.protocol.McpRequests;
import com.mcpscanner.http.BareRequests;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.BurpStreamingRefusal;

import java.net.URI;
import java.util.Optional;

final class AuthChallengeRequest {

    private static final String PROBE_CLIENT_NAME = "mcp-server-scanner-auth-probe";
    private static final String PROBE_CLIENT_VERSION = "1";
    private static final String SESSION_ID_HEADER = "Mcp-Session-Id";

    private final Http http;
    private final McpEventLog eventLog;

    AuthChallengeRequest(Http http, McpEventLog eventLog) {
        this.http = http;
        this.eventLog = eventLog != null ? eventLog : McpEventLog.noop();
    }

    ChallengeReply send(URI mcpResource) {
        try {
            return replyTo(mcpResource);
        } catch (RuntimeException failure) {
            if (BurpStreamingRefusal.refused(failure)) {
                return new ChallengeReply.Streamed();
            }
            throw failure;
        }
    }

    private ChallengeReply replyTo(URI mcpResource) {
        HttpResponse response = http.sendRequest(initializeTo(mcpResource), DiscoveryRequestOptions.noRedirect())
                .response();
        if (response == null) {
            return new ChallengeReply.Silent();
        }
        closeSessionOpenedBy(response, mcpResource);
        return new ChallengeReply.Answered(response);
    }

    private void closeSessionOpenedBy(HttpResponse response, URI mcpResource) {
        Optional.ofNullable(response.headerValue(SESSION_ID_HEADER))
                .ifPresent(sessionId -> deleteSession(mcpResource, sessionId));
    }

    private void deleteSession(URI mcpResource, String sessionId) {
        try {
            http.sendRequest(BareRequests.fromUrl(mcpResource.toString()).withMethod("DELETE")
                    .withAddedHeader(SESSION_ID_HEADER, sessionId), DiscoveryRequestOptions.noRedirect());
        } catch (RuntimeException failure) {
            eventLog.warn("Could not close the auth probe's MCP session on " + mcpResource + ": "
                    + failure.getMessage());
        }
    }

    private static HttpRequest initializeTo(URI mcpResource) {
        McpRequests.Request initialize = McpRequests.initialize(McpRequests.HANDSHAKE_VERSION,
                ClientProfile.of(PROBE_CLIENT_NAME, PROBE_CLIENT_VERSION));
        HttpRequest request = BareRequests.fromUrl(mcpResource.toString()).withMethod("POST");
        for (var header : initialize.headers().entrySet()) {
            request = request.withAddedHeader(header.getKey(), header.getValue());
        }
        return request.withBody(initialize.body());
    }
}
