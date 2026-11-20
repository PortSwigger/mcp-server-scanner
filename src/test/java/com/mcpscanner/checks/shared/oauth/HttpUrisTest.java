package com.mcpscanner.checks.shared.oauth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

class HttpUrisTest {

    @Test
    void parsesHttpAndHttpsUrls() {
        assertThat(HttpUris.parse(" https://as.example/authorize ")).contains(URI.create("https://as.example/authorize"));
        assertThat(HttpUris.parse("http://127.0.0.1:8000/mcp")).isPresent();
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://as.example.com/x", "http://as.example.com", "HTTPS://as.example.com:8443/"})
    void parsesHttpAndHttpsUrlsWithAHost(String value) {
        assertThat(HttpUris.parse(value)).contains(URI.create(value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "javascript:alert(1)", "data:text/html,x", "/relative", "https://user@as.example/",
            "ht tp://bad", "mailto:a@b.example", "ftp://as.example.com/", "https:///no-host",
            "https://as.example.com/a b"})
    void rejectsNonHttpRelativeHostlessOrCredentialedUrls(String value) {
        assertThat(HttpUris.parse(value)).isEmpty();
    }

    @Test
    void rejectsNull() {
        assertThat(HttpUris.parse(null)).isEmpty();
    }

    @Test
    void originDropsDefaultPortsAndNormalisesCase() {
        assertThat(HttpUris.origin(URI.create("HTTPS://AS.Example:443/x?y"))).isEqualTo("https://as.example");
        assertThat(HttpUris.origin(URI.create("http://as.example:8080/x"))).isEqualTo("http://as.example:8080");
        assertThat(HttpUris.origin(URI.create("http://[::1]:8080/x"))).isEqualTo("http://[::1]:8080");
        assertThat(HttpUris.origin(URI.create("http://[::1]/x"))).isEqualTo("http://[::1]");
    }

    @ParameterizedTest
    @CsvSource({
            "HTTPS://AS.Example.COM/path, https://as.example.com",
            "https://as.example.com:443/, https://as.example.com",
            "http://as.example.com:80/, http://as.example.com",
            "https://as.example.com:8443/, https://as.example.com:8443",
            "http://as.example.com:443/, http://as.example.com:443"})
    void originLowercasesAndDropsOnlyTheDefaultPort(String uri, String origin) {
        assertThat(HttpUris.origin(URI.create(uri))).isEqualTo(origin);
    }

    @Test
    void sameOriginComparesSchemeHostAndEffectivePort() {
        assertThat(HttpUris.sameOrigin(URI.create("https://a.example/x"), URI.create("https://a.example:443/y")))
                .isTrue();
        assertThat(HttpUris.sameOrigin(URI.create("https://a.example/x"), URI.create("http://a.example/x")))
                .isFalse();
        assertThat(HttpUris.sameOrigin(URI.create("https://a.example/x"), URI.create("https://b.example/x")))
                .isFalse();
    }

    @Test
    void resolvesRelativeReferencesAgainstABase() {
        assertThat(HttpUris.resolve(URI.create("https://as.example/oauth/authorize"), "consent?x=1"))
                .contains(URI.create("https://as.example/oauth/consent?x=1"));
        assertThat(HttpUris.resolve(URI.create("https://as.example/a"), "javascript:alert(1)")).isEmpty();
    }

    @Test
    void withoutQueryKeepsOriginAndPathOnly() {
        assertThat(HttpUris.withoutQuery(URI.create("https://as.example:443/authorize?state=x#f")))
                .isEqualTo("https://as.example/authorize");
        assertThat(HttpUris.withoutQuery(URI.create("http://as.example:8080?x=1"))).isEqualTo("http://as.example:8080/");
    }

    @ParameterizedTest
    @CsvSource({
            "https://as.example.com/tenant/, /tenant",
            "https://as.example.com/tenant, /tenant",
            "https://as.example.com/, ''",
            "https://as.example.com, ''",
            "https://as.example.com/a%20b/, /a%20b"})
    void pathWithoutTrailingSlashKeepsTheRawPath(String uri, String path) {
        assertThat(HttpUris.pathWithoutTrailingSlash(URI.create(uri))).isEqualTo(path);
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://as.example.com/authorize", "HTTPS://10.0.0.5/authorize",
            "http://127.0.0.1:8000/authorize", "http://localhost/authorize", "http://LOCALHOST:9000/",
            "http://[::1]:8080/authorize", "http://127.4.5.6/authorize"})
    void secureOrLoopbackWhenHttpsOrALoopbackHost(String uri) {
        assertThat(HttpUris.isSecureOrLoopback(URI.create(uri))).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://as.example.com/authorize", "http://10.0.0.5/authorize",
            "http://192.168.1.10:8080/authorize", "http://localhost.example.com/", "http://128.0.0.1/"})
    void notSecureOrLoopbackOverPlainHttpToAnyOtherHost(String uri) {
        assertThat(HttpUris.isSecureOrLoopback(URI.create(uri))).isFalse();
    }
}
