package com.mcpscanner.auth.oauth;

import com.mcpscanner.auth.oauth.safety.HostResolver;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OAuthUrlValidatorTest {

    private final OAuthUrlValidator validator = new OAuthUrlValidator();

    @Test
    void rejectsAwsMetadataLinkLocalAddress() {
        assertThatThrownBy(() -> validator.validate(URI.create("http://169.254.169.254/")))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("link-local");
    }

    @Test
    void rejectsPrivateRangeIpv4() {
        assertThatThrownBy(() -> validator.validate(URI.create("http://10.0.0.1/")))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("private");
    }

    @Test
    void rejectsRfc1918Range172() {
        assertThatThrownBy(() -> validator.validate(URI.create("http://172.16.5.5/")))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("private");
    }

    @Test
    void rejectsMulticastAddress() {
        assertThatThrownBy(() -> validator.validate(URI.create("http://224.0.0.1/")))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("multicast");
    }

    @Test
    void rejectsUnspecifiedAddress() {
        assertThatThrownBy(() -> validator.validate(URI.create("http://0.0.0.0/")))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void rejectsHttpForNonLoopbackHost() {
        assertThatThrownBy(() -> validator.validate(URI.create("http://issuer.example.com/")))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("https");
    }

    @Test
    void rejectsJavascriptScheme() {
        assertThatThrownBy(() -> validator.validate(URI.create("javascript:alert(1)")))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void rejectsFileScheme() {
        assertThatThrownBy(() -> validator.validate(URI.create("file:///etc/passwd")))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void rejectsPortZero() {
        assertThatThrownBy(() -> validator.validate(URI.create("https://issuer.example.com:0/")))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("port");
    }

    @Test
    void rejectsMissingHost() {
        assertThatThrownBy(() -> validator.validate(URI.create("https:///path")))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void acceptsHttpsPublicHost() {
        assertThatCode(() -> validator.validate(URI.create("https://issuer.example.com/path")))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsHttpLoopbackByLiteralIpv4() {
        assertThatCode(() -> validator.validate(URI.create("http://127.0.0.1:8080/callback")))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsHttpLoopbackByLocalhost() {
        assertThatCode(() -> validator.validate(URI.create("http://localhost:8080/callback")))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsHttpLoopbackByIpv6Literal() {
        assertThatCode(() -> validator.validate(URI.create("http://[::1]:8080/callback")))
                .doesNotThrowAnyException();
    }

    @Test
    void classifyReturnsCloudMetadataForImdsAddress() {
        assertThat(validator.classify(URI.create("http://169.254.169.254/latest/meta-data")))
                .contains(OAuthUrlValidator.CLASSIFICATION_CLOUD_METADATA);
    }

    @Test
    void classifyReturnsLinkLocalForOtherLinkLocalAddress() {
        assertThat(validator.classify(URI.create("http://169.254.10.1/")))
                .contains(OAuthUrlValidator.CLASSIFICATION_LINK_LOCAL);
    }

    @Test
    void classifyReturnsLoopbackForLocalhostUri() {
        assertThat(validator.classify(URI.create("https://127.0.0.1:8443/")))
                .contains(OAuthUrlValidator.CLASSIFICATION_LOOPBACK);
    }

    @Test
    void classifyReturnsPrivateForRfc1918Address() {
        assertThat(validator.classify(URI.create("https://10.0.0.1/")))
                .contains(OAuthUrlValidator.CLASSIFICATION_PRIVATE);
    }

    @Test
    void classifyReturnsPrivateForIpv6UniqueLocalAddress() {
        assertThat(validator.classify(URI.create("https://[fd00::1]/")))
                .contains(OAuthUrlValidator.CLASSIFICATION_PRIVATE);
    }

    @Test
    void classifyReturnsHttpDowngradeForPlainHttpPublicHost() {
        assertThat(validator.classify(URI.create("http://issuer.example.com/")))
                .contains(OAuthUrlValidator.CLASSIFICATION_HTTP_DOWNGRADE);
    }

    @Test
    void classifyReturnsEmptyForCleanHttpsUrl() {
        Optional<String> classification = validator.classify(URI.create("https://issuer.example.com/.well-known/openid-configuration"));
        assertThat(classification).isEmpty();
    }

    @Test
    void classifyReturnsMissingSchemeOrHostForNullUri() {
        assertThat(validator.classify(null)).contains(OAuthUrlValidator.CLASSIFICATION_MISSING_SCHEME_OR_HOST);
    }

    @Test
    void classifyReturnsMissingSchemeOrHostForOpaqueJavascriptUri() {
        assertThat(validator.classify(URI.create("javascript:alert(1)")))
                .contains(OAuthUrlValidator.CLASSIFICATION_MISSING_SCHEME_OR_HOST);
    }

    @Test
    void classifyReturnsInvalidSchemeForFtpUrl() {
        assertThat(validator.classify(URI.create("ftp://files.example.com/path")))
                .contains(OAuthUrlValidator.CLASSIFICATION_INVALID_SCHEME);
    }

    @Test
    void classifyReturnsInvalidPortForPortZero() {
        assertThat(validator.classify(URI.create("https://issuer.example.com:0/")))
                .contains(OAuthUrlValidator.CLASSIFICATION_INVALID_PORT);
    }

    @Test
    void validateRejectsLoopbackWithPortZero() {
        assertThatThrownBy(() -> validator.validate(URI.create("http://127.0.0.1:0/")))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void validateRejectsInvalidSchemeEvenOnLoopbackHost() {
        assertThatThrownBy(() -> validator.validate(URI.create("ftp://localhost/callback")))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("https");
    }

    @Test
    void validateRejectsJavascriptSchemeWithLoopbackHost() {
        assertThatThrownBy(() -> validator.validate(URI.create("javascript://localhost/callback")))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("https");
    }

    @Test
    void classifyAllHostnameResolvesToLoopbackReturnsLoopback() {
        HostResolver resolver = stubResolver("oauth.example.test", "127.0.0.1");

        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("https://oauth.example.test/.well-known/oauth-authorization-server"),
                        resolver, null);

        assertThat(classification.codes()).contains(OAuthUrlValidator.CLASSIFICATION_LOOPBACK);
        assertThat(classification.resolvedAddress()).isEqualTo("127.0.0.1");
    }

    @Test
    void classifyAllHostnameResolvesToRfc1918ReturnsPrivate() {
        HostResolver resolver = stubResolver("internal.corp", "10.0.0.5");

        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("https://internal.corp/auth"), resolver, null);

        assertThat(classification.codes()).contains(OAuthUrlValidator.CLASSIFICATION_PRIVATE);
        assertThat(classification.resolvedAddress()).isEqualTo("10.0.0.5");
    }

    @Test
    void classifyAllHostnameResolvesToCloudMetadataReturnsCloudMetadata() {
        HostResolver resolver = stubResolver("metadata.attacker.test", "169.254.169.254");

        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("https://metadata.attacker.test/latest/meta-data"),
                        resolver, null);

        assertThat(classification.codes()).contains(OAuthUrlValidator.CLASSIFICATION_CLOUD_METADATA);
    }

    @Test
    void classifyAllCleanPublicHostReturnsEmptyCodes() {
        HostResolver resolver = stubResolver("auth.example.com", "203.0.113.10");

        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("https://auth.example.com/authorize"), resolver, null);

        assertThat(classification.codes()).isEmpty();
        assertThat(classification.isClean()).isTrue();
    }

    @Test
    void classifyAllCrossOriginRelativeToMcpEndpoint() {
        HostResolver resolver = stubResolver("auth.other.com", "203.0.113.20");
        URI mcpOrigin = URI.create("https://mcp.example.com/mcp");

        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("https://auth.other.com/authorize"), resolver, mcpOrigin);

        assertThat(classification.codes()).contains(OAuthUrlValidator.CLASSIFICATION_CROSS_ORIGIN);
    }

    @Test
    void classifyAllSameOriginAsMcpEndpointHasNoCrossOriginCode() {
        HostResolver resolver = stubResolver("mcp.example.com", "203.0.113.30");
        URI mcpOrigin = URI.create("https://mcp.example.com/mcp");

        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("https://mcp.example.com/authorize"), resolver, mcpOrigin);

        assertThat(classification.codes()).doesNotContain(OAuthUrlValidator.CLASSIFICATION_CROSS_ORIGIN);
        assertThat(classification.codes()).isEmpty();
    }

    @Test
    void classifyAllDnsTimeoutReturnsUnresolvable() {
        HostResolver timingOut = host -> {
            throw new HostResolver.ResolutionTimeoutException("timed out");
        };

        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("https://slow.example.com/"), timingOut, null);

        assertThat(classification.codes()).contains(OAuthUrlValidator.CLASSIFICATION_UNRESOLVABLE);
    }

    @Test
    void classifyAllPlainHttpToPublicHostReturnsPlainHttpNonLoopback() {
        HostResolver resolver = stubResolver("auth.example.com", "203.0.113.10");

        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("http://auth.example.com/"), resolver, null);

        assertThat(classification.codes()).contains(OAuthUrlValidator.CLASSIFICATION_PLAIN_HTTP_NON_LOOPBACK);
    }

    @Test
    void classifyAll_plainHttpToPublicHost_includesPlainHttp() {
        HostResolver resolver = stubResolver("example.com", "203.0.113.5");

        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("http://example.com/x"), resolver, null);

        assertThat(classification.codes()).contains(OAuthUrlValidator.CLASSIFICATION_PLAIN_HTTP_NON_LOOPBACK);
    }

    @Test
    void classifyAll_plainHttpToLoopback_excludesPlainHttp() {
        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("http://127.0.0.1:8080/x"), null, null);

        assertThat(classification.codes()).contains(OAuthUrlValidator.CLASSIFICATION_LOOPBACK);
        assertThat(classification.codes()).doesNotContain(OAuthUrlValidator.CLASSIFICATION_PLAIN_HTTP_NON_LOOPBACK);
    }

    @Test
    void classifyAll_httpsToPublicHost_excludesPlainHttp() {
        HostResolver resolver = stubResolver("example.com", "203.0.113.5");

        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("https://example.com/x"), resolver, null);

        assertThat(classification.codes()).doesNotContain(OAuthUrlValidator.CLASSIFICATION_PLAIN_HTTP_NON_LOOPBACK);
    }

    @Test
    void classifyAll_plainHttpToRfc1918_bothClassificationsPresent() {
        HostResolver resolver = stubResolver("internal.corp", "10.0.0.5");

        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("http://internal.corp/x"), resolver, null);

        assertThat(classification.codes()).contains(OAuthUrlValidator.CLASSIFICATION_PRIVATE);
        assertThat(classification.codes()).contains(OAuthUrlValidator.CLASSIFICATION_PLAIN_HTTP_NON_LOOPBACK);
    }

    @Test
    void classifyAllInvalidSchemeIsHardBlockBeforeResolution() {
        HostResolver resolver = stubResolver("files.example.com", "203.0.113.10");

        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("ftp://files.example.com/path"), resolver, null);

        assertThat(classification.codes()).containsExactly(OAuthUrlValidator.CLASSIFICATION_INVALID_SCHEME);
    }

    @Test
    void classifyAllMissingHostIsHardBlock() {
        OAuthUrlValidator.Classification classification =
                validator.classifyAll(URI.create("https:///path"), stubResolver("anything", "127.0.0.1"), null);

        assertThat(classification.codes()).containsExactly(OAuthUrlValidator.CLASSIFICATION_MISSING_SCHEME_OR_HOST);
    }

    private static HostResolver stubResolver(String host, String address) {
        return new StubHostResolver(Map.of(host, List.of(byAddress(host, address))));
    }

    private static InetAddress byAddress(String host, String address) {
        try {
            String[] parts = address.split("\\.");
            byte[] bytes = new byte[4];
            for (int i = 0; i < 4; i++) {
                bytes[i] = (byte) Integer.parseInt(parts[i]);
            }
            return InetAddress.getByAddress(host, bytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private record StubHostResolver(Map<String, List<InetAddress>> fixture) implements HostResolver {
        @Override
        public List<InetAddress> resolve(String host) {
            return fixture.getOrDefault(host, List.of());
        }
    }
}
