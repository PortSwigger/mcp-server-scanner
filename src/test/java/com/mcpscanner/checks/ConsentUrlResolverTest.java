package com.mcpscanner.checks;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ConsentUrlResolverTest {

    private static final URI AS_ORIGIN = URI.create("https://mcp.example.com");

    private final ConsentUrlResolver resolver = new ConsentUrlResolver();

    @Test
    void crossOriginLoginBounce_extractsAsOriginConsentUrlFromPostSignUp() {
        String location = "https://users.example.com/signin"
                + "?postSignUp=https%3A%2F%2Fmcp.example.com%2Fauthorize%2Fconsent%3Fstate%3Dabc123"
                + "&redirectTo=https%3A%2F%2Fmcp.example.com%2Fauthorize%3Fclient_id%3Dxyz";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).hasValue(URI.create("https://mcp.example.com/authorize/consent?state=abc123"));
    }

    @Test
    void redirectToParamCarriesConsentUrl_extractsIt() {
        String location = "https://users.example.com/signin"
                + "?redirectTo=https%3A%2F%2Fmcp.example.com%2Fauthorize%2Fconsent%3Fstate%3Dxyz";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).hasValue(URI.create("https://mcp.example.com/authorize/consent?state=xyz"));
    }

    @Test
    void doublyEncodedConsentUrl_isUrlDecoded() {
        // postSignUp value is itself percent-encoded once inside the Location query string.
        String location = "https://login.example.com/signin"
                + "?continue=https%3A%2F%2Fmcp.example.com%2Fauthorize%2Fconsent%3Fstate%3Da%2526b";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).hasValue(URI.create("https://mcp.example.com/authorize/consent?state=a%26b"));
    }

    @Test
    void crossOriginEmbeddedConsentUrl_returnsEmpty() {
        String location = "https://users.example.com/signin"
                + "?postSignUp=https%3A%2F%2Fevil.example.com%2Fauthorize%2Fconsent";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).isEmpty();
    }

    @Test
    void differentHostSameSchemeEmbeddedConsentUrl_returnsEmpty() {
        String location = "https://users.example.com/signin"
                + "?postSignUp=https%3A%2F%2Fother.example.com%2Fauthorize%2Fconsent";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).isEmpty();
    }

    @Test
    void loopbackEmbeddedConsentUrl_returnsEmpty() {
        String location = "https://users.example.com/signin"
                + "?postSignUp=http%3A%2F%2F127.0.0.1%3A53682%2Fauthorize%2Fconsent";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).isEmpty();
    }

    @Test
    void schemeDowngradeEmbeddedConsentUrl_returnsEmpty() {
        String location = "https://users.example.com/signin"
                + "?postSignUp=http%3A%2F%2Fmcp.example.com%2Fauthorize%2Fconsent";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).isEmpty();
    }

    @Test
    void noConsentParamPresent_returnsEmpty() {
        String location = "https://users.example.com/signin?foo=bar&baz=qux";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).isEmpty();
    }

    @Test
    void multipleParams_picksTheAsOriginCandidate() {
        // redirectTo is cross-origin (the sign-in app's own return URL); postSignUp is the AS-origin
        // consent URL. The resolver must pick the AS-origin one, not the first param it sees.
        String location = "https://users.example.com/signin"
                + "?redirectTo=https%3A%2F%2Fusers.example.com%2Faccount"
                + "&postSignUp=https%3A%2F%2Fmcp.example.com%2Fauthorize%2Fconsent%3Fstate%3Dpicked";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).hasValue(URI.create("https://mcp.example.com/authorize/consent?state=picked"));
    }

    @Test
    void nullLocation_returnsEmpty() {
        Optional<URI> consent = resolver.resolve(null, AS_ORIGIN);

        assertThat(consent).isEmpty();
    }

    @Test
    void blankLocation_returnsEmpty() {
        Optional<URI> consent = resolver.resolve("   ", AS_ORIGIN);

        assertThat(consent).isEmpty();
    }

    @Test
    void embeddedConsentUrlEqualToAsOriginRoot_isAccepted() {
        String location = "https://login.example.com/signin"
                + "?next=https%3A%2F%2Fmcp.example.com%2Fauthorize%2Fconsent";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).hasValue(URI.create("https://mcp.example.com/authorize/consent"));
    }

    @Test
    void asOriginWithExplicitPort_matchesEmbeddedConsentUrlWithSamePort() {
        URI asOrigin = URI.create("https://mcp.example.com:8443");
        String location = "https://login.example.com/signin"
                + "?postSignUp=https%3A%2F%2Fmcp.example.com%3A8443%2Fauthorize%2Fconsent";

        Optional<URI> consent = resolver.resolve(location, asOrigin);

        assertThat(consent).hasValue(URI.create("https://mcp.example.com:8443/authorize/consent"));
    }

    @Test
    void callbackParamCarriesConsentUrl_extractsIt() {
        // 'callback' is NOT in the old hardcoded allowlist. Param-agnostic discovery must find it.
        String location = "https://login.example.com/signin"
                + "?callback=https%3A%2F%2Fmcp.example.com%2Fauthorize%2Fconsent%3Fstate%3Dcb";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).hasValue(URI.create("https://mcp.example.com/authorize/consent?state=cb"));
    }

    @Test
    void gotoParamCarriesConsentUrl_extractsIt() {
        String location = "https://login.example.com/signin"
                + "?goto=https%3A%2F%2Fmcp.example.com%2Fauthorize%2Fconsent%3Fstate%3Dgo";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).hasValue(URI.create("https://mcp.example.com/authorize/consent?state=go"));
    }

    @Test
    void targetLinkUriParamCarriesConsentUrl_extractsIt() {
        String location = "https://login.example.com/signin"
                + "?target_link_uri=https%3A%2F%2Fmcp.example.com%2Fauthorize%2Fconsent";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).hasValue(URI.create("https://mcp.example.com/authorize/consent"));
    }

    @Test
    void afterSignInUrlParamCarriesConsentUrl_extractsIt() {
        String location = "https://login.example.com/signin"
                + "?after_sign_in_url=https%3A%2F%2Fmcp.example.com%2Fauthorize%2Fconsent";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).hasValue(URI.create("https://mcp.example.com/authorize/consent"));
    }

    @Test
    void embeddedRelativeUrl_returnsEmpty() {
        // A relative path has no origin to verify against the AS origin; refuse it (no base to
        // safely resolve against in the pure helper — the direct same-origin hop handles relatives).
        String location = "https://login.example.com/signin?postSignUp=%2Fauthorize%2Fconsent";

        Optional<URI> consent = resolver.resolve(location, AS_ORIGIN);

        assertThat(consent).isEmpty();
    }
}
