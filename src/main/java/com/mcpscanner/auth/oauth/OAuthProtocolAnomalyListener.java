package com.mcpscanner.auth.oauth;

import java.net.URI;

/**
 * @deprecated Use {@link OAuthMetadataConsistencyListener} instead. This alias is kept only for
 *     binary compatibility with existing call sites; it will be removed in a future release.
 */
@Deprecated
@FunctionalInterface
public interface OAuthProtocolAnomalyListener extends OAuthMetadataConsistencyListener {

    /**
     * {@inheritDoc}
     */
    @Override
    void onIssuerMismatch(URI metadataUrl,
                          String expectedIssuer,
                          String returnedIssuer,
                          byte[] rawResponseBody);

    /**
     * Returns a listener that ignores every callback.
     *
     * @deprecated Use {@link OAuthMetadataConsistencyListener#noop()} instead.
     */
    @Deprecated
    static OAuthProtocolAnomalyListener noop() {
        return (metadataUrl, expectedIssuer, returnedIssuer, rawResponseBody) -> {};
    }
}
