package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.Http;
import com.mcpscanner.logging.McpEventLog;

import java.net.URI;
import java.util.Optional;
import java.util.regex.Pattern;

public final class AuthRequirementProbe {

    private static final Pattern BEARER_SCHEME = Pattern.compile("(?i)(^|[\\s,])bearer(\\s|,|$)");
    private static final String NO_OAUTH_ANSWER = "The server needs credentials and advertises no OAuth sign-in";
    private static final String NO_RESPONSE_REASON =
            "Server did not answer the unauthenticated probe — check the endpoint, or choose an auth type manually";

    private final ChallengeSender post;
    private final ChallengeSender streamGet;
    private final OAuthMetadataDiscoverer discoverer;

    public AuthRequirementProbe(Http http, OAuthMetadataDiscoverer discoverer) {
        this(http, discoverer, McpEventLog.noop());
    }

    public AuthRequirementProbe(Http http, OAuthMetadataDiscoverer discoverer, McpEventLog eventLog) {
        this(new PostChallengeSender(http, eventLog), new StreamGetChallengeSender(), discoverer);
    }

    AuthRequirementProbe(ChallengeSender post, ChallengeSender streamGet, OAuthMetadataDiscoverer discoverer) {
        this.post = post;
        this.streamGet = streamGet;
        this.discoverer = discoverer;
    }

    public AuthRequirement probe(URI mcpResource, ChallengeStrategy strategy) {
        boolean answered = false;
        for (ChallengeSender sender : strategy.sendersFrom(post, streamGet)) {
            Optional<ChallengeResponse> response = trySend(sender, mcpResource);
            answered |= response.isPresent();
            if (response.isPresent() && response.get().requiresAuth()) {
                return classify(response.get(), mcpResource);
            }
            if (response.isPresent() && response.get().succeeded()) {
                return new AuthRequirement.NotRequired();
            }
        }
        return answered ? new AuthRequirement.NotRequired() : new AuthRequirement.Unsupported(NO_RESPONSE_REASON);
    }

    private static Optional<ChallengeResponse> trySend(ChallengeSender sender, URI mcpResource) {
        try {
            return sender.send(mcpResource);
        } catch (RuntimeException unreachable) {
            return Optional.empty();
        }
    }

    private AuthRequirement classify(ChallengeResponse response, URI mcpResource) {
        if (response.challenge().isPresent() && !BEARER_SCHEME.matcher(response.challenge().get()).find()) {
            return new AuthRequirement.CredentialsRequired(nonBearerAnswer(response.challenge().get()), false);
        }
        return discoverOAuth(mcpResource);
    }

    private AuthRequirement discoverOAuth(URI mcpResource) {
        try {
            return new AuthRequirement.OAuth(discoverer.discover(mcpResource));
        } catch (DiscoveryFailedException noMetadata) {
            return new AuthRequirement.CredentialsRequired(NO_OAUTH_ANSWER, true);
        }
    }

    private static String nonBearerAnswer(String challenge) {
        String scheme = challenge.trim().split("[\\s,]", 2)[0];
        return "The server challenges with " + scheme + ", not OAuth";
    }
}
