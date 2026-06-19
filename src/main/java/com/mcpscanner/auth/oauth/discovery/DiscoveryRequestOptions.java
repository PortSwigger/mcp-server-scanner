package com.mcpscanner.auth.oauth.discovery;

import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;

/**
 * Shared {@link RequestOptions} for OAuth metadata discovery fetches sent through Burp's
 * {@code api.http()}. {@link RedirectionMode#NEVER} preserves the prior {@code Redirect.NEVER}
 * SSRF guard: discovery must never follow a redirect out from under the SuspiciousDestinationGate.
 *
 * <p>Resolved lazily (rather than as an eagerly-initialised constant) so the Montoya object
 * factory only needs to be available when a request is actually sent, not at class load.
 */
final class DiscoveryRequestOptions {

    static RequestOptions noRedirect() {
        return RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.NEVER);
    }

    private DiscoveryRequestOptions() {
    }
}
