package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.http.BareRequests;
import com.mcpscanner.http.EmptyResponse;
import com.mcpscanner.mcp.BurpStreamingRefusal;

import java.net.URI;
import java.time.Duration;
import java.util.Optional;

final class BurpStreamGetChallengeSender implements ChallengeSender {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final Http http;

    BurpStreamGetChallengeSender(Http http) {
        this.http = http;
    }

    @Override
    public Optional<ChallengeResponse> send(URI mcpResource) {
        return replyTo(mcpResource).asChallengeResponse();
    }

    private ChallengeReply replyTo(URI mcpResource) {
        try {
            HttpResponse response = http.sendRequest(streamGet(mcpResource),
                    DiscoveryRequestOptions.noRedirect().withResponseTimeout(TIMEOUT.toMillis())).response();
            return unanswered(response) ? new ChallengeReply.Silent() : new ChallengeReply.Answered(response);
        } catch (RuntimeException failure) {
            if (BurpStreamingRefusal.refused(failure)) {
                return new ChallengeReply.Streamed();
            }
            throw failure;
        }
    }

    private static boolean unanswered(HttpResponse response) {
        return response == null || EmptyResponse.is(response);
    }

    private static HttpRequest streamGet(URI mcpResource) {
        return BareRequests.fromUrl(mcpResource.toString()).withMethod("GET")
                .withAddedHeader("Accept", "text/event-stream");
    }
}
