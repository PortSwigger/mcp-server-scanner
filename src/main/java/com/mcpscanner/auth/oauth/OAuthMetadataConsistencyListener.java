package com.mcpscanner.auth.oauth;

import java.net.URI;

/**
 * Receives notifications about OAuth metadata consistency anomalies observed during discovery
 * and authorization flows. Implementations should treat each callback as a best-effort hook
 * for surfacing the anomaly (e.g. emitting a Burp audit issue) — they must not assume the
 * connect flow has finished, and exceptions thrown from a listener must never propagate out
 * of the caller.
 *
 * <p>Three categories of anomaly are defined:
 * <ol>
 *   <li><b>Issuer mismatch (RFC 8414 §3.3)</b> — the AS metadata document declares an
 *       {@code issuer} that does not match the well-known URL the document was fetched from.</li>
 *   <li><b>PRM cross-domain authorization server</b> — the PRM document's
 *       {@code authorization_servers[0]} URL is on a different host than the MCP endpoint.</li>
 *   <li><b>AS endpoint host mismatch</b> — an endpoint advertised in the AS metadata document
 *       (e.g. {@code authorization_endpoint}) is on a different host than the AS issuer.</li>
 * </ol>
 */
public interface OAuthMetadataConsistencyListener {

    /**
     * Invoked when the authorization-server metadata document violates RFC 8414 §3.3 by
     * declaring an {@code issuer} that does not match the well-known URL the document was
     * fetched from, and the flow recovered via the lenient fallback.
     *
     * @param metadataUrl     the URL the metadata document was fetched from
     * @param expectedIssuer  the issuer value the well-known URL was derived from
     * @param returnedIssuer  the issuer the metadata document declared (or {@code "<missing>"}
     *                        if the document had no {@code issuer} field)
     * @param rawResponseBody the verbatim bytes of the metadata response — never {@code null}
     */
    void onIssuerMismatch(URI metadataUrl,
                          String expectedIssuer,
                          String returnedIssuer,
                          byte[] rawResponseBody);

    /**
     * Invoked when the PRM document's {@code authorization_servers[0]} URL is hosted on a
     * different domain than the MCP endpoint that served the PRM document. This may indicate
     * a misconfiguration or a metadata-level redirect to an unrelated authorization server.
     *
     * @param prmDocUrl            the URL the PRM document was fetched from
     * @param mcpEndpointHost      the host of the MCP endpoint that triggered discovery
     * @param authorizationServerUrl the raw {@code authorization_servers[0]} value from the PRM
     * @param rawPrmBody           the verbatim bytes of the PRM response — never {@code null}
     */
    default void onPrmAuthorizationServerHostMismatch(URI prmDocUrl,
                                                       String mcpEndpointHost,
                                                       String authorizationServerUrl,
                                                       byte[] rawPrmBody) {
    }

    /**
     * Invoked when an endpoint advertised in the AS metadata document (e.g.
     * {@code authorization_endpoint}, {@code token_endpoint}, or
     * {@code registration_endpoint}) is hosted on a different domain than the AS issuer
     * declared in the same document.
     *
     * @param metadataUrl  the URL the AS metadata document was fetched from
     * @param asIssuer     the {@code issuer} value declared by the AS metadata document
     * @param endpointName the field name of the mismatched endpoint
     * @param endpointUrl  the URL value of the mismatched endpoint
     * @param rawAsBody    the verbatim bytes of the AS metadata response — never {@code null}
     */
    default void onAsEndpointHostMismatch(URI metadataUrl,
                                           String asIssuer,
                                           String endpointName,
                                           String endpointUrl,
                                           byte[] rawAsBody) {
    }

    /**
     * Returns a listener that ignores every callback. Use as the default when no observer
     * is wired so call sites do not need null-checks.
     */
    static OAuthMetadataConsistencyListener noop() {
        return NoopHolder.INSTANCE;
    }

    final class NoopHolder {
        private static final OAuthMetadataConsistencyListener INSTANCE =
                new OAuthMetadataConsistencyListener() {
                    @Override
                    public void onIssuerMismatch(URI metadataUrl, String expectedIssuer,
                                                  String returnedIssuer, byte[] rawResponseBody) {}
                };

        private NoopHolder() {}
    }
}
