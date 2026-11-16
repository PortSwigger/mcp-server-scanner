package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import com.mcpscanner.logging.McpEventLog;

import java.net.URI;
import java.util.Optional;

final class PostChallengeSender implements ChallengeSender {

    private final AuthChallengeRequest request;

    PostChallengeSender(Http http, McpEventLog eventLog) {
        this.request = new AuthChallengeRequest(http, eventLog);
    }

    @Override
    public Optional<ChallengeResponse> send(URI mcpResource) {
        return request.send(mcpResource).asChallengeResponse();
    }
}
