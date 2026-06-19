package com.mcpscanner.checks;

import java.net.URI;

/**
 * Describes a single OAuth authorization-code {@code GET /authorize} probe: which authorization
 * endpoint to hit, with which client, redirect target, and (optional) scope. The runner supplies
 * the volatile per-request parameters (PKCE challenge, state) so this stays a pure value object
 * reusable by any check that needs to drive an authorization request.
 */
public record AuthorizeProbe(URI authorizationEndpoint,
                             String clientId,
                             String redirectUri,
                             String scope) {
}
