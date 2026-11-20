package com.mcpscanner.signedin;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ProxyHistoryCookieOriginsTest {

    private final List<ProxyHttpRequestResponse> history = new ArrayList<>();
    private final CookieOrigins origins = new ProxyHistoryCookieOrigins(
            filter -> history.stream().filter(filter::matches).toList());

    @Test
    void aCookieSetWithADomainAttributeByASubdomainIsForTheWholeDomain() {
        proxied("auth.example.com", "/login", "sid=1; Domain=example.com; Path=/");

        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/", "sid", "1"))).isTrue();
    }

    @Test
    void aDottedDomainAttributeThatBurpStoresWithoutItsDotIsForTheWholeDomain() {
        proxied("auth.example.com", "/login", "sid=1; Path=/; domain=.EXAMPLE.com");

        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/", "sid", "1"))).isTrue();
    }

    @Test
    void aHostOnlyCookieOfTheParentHostIsNotForTheWholeDomain() {
        proxied("example.com", "/", "sid=1; Path=/");

        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/", "sid", "1"))).isFalse();
    }

    @Test
    void aCookieTheHistoryDoesNotExplainIsNotForTheWholeDomain() {
        proxied("auth.example.com", "/login", "other=1; Domain=example.com; Path=/");

        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/", "sid", "1"))).isFalse();
    }

    @Test
    void theLatestSetCookieThatProducedTheJarEntryDecides() {
        proxied("auth.example.com", "/login", "sid=1; Domain=example.com; Path=/");
        proxied("example.com", "/", "sid=2; Path=/");

        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/", "sid", "2"))).isFalse();

        proxied("auth.example.com", "/login", "sid=3; Domain=example.com; Path=/");

        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/", "sid", "3"))).isTrue();
    }

    @Test
    void aJarValueTheHistoryNeverSetIsNotForTheWholeDomain() {
        proxied("auth.example.com", "/login", "sid=A; Domain=example.com; Path=/");

        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/", "sid", "B"))).isFalse();
    }

    @Test
    void theSetCookieThatWroteTheJarValueDecidesWhateverTheHistoryOrder() {
        proxied("example.com", "/", "sid=B; Path=/");
        proxied("auth.example.com", "/login", "sid=A; Domain=example.com; Path=/");

        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/", "sid", "B"))).isFalse();
    }

    @Test
    void aHostOnlyCookieWhosePathBurpMayStoreDifferentlyIsNeverExplainedByAnotherValue() {
        proxied("auth.example.com", "/login", "sid=A; Domain=example.com; Path=/");
        proxied("example.com", "/a/b", "sid=B");

        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/", "sid", "B"))).isFalse();
    }

    @Test
    void aSameNamedCookieOnAnotherPathIsAnotherJarEntry() {
        proxied("example.com", "/", "sid=1; Path=/account");
        proxied("auth.example.com", "/login", "sid=2; Domain=example.com; Path=/");

        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/account", "sid", "1"))).isFalse();
        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/", "sid", "2"))).isTrue();
    }

    @Test
    void aCookieWithoutAPathAttributeTakesTheDirectoryOfTheRequestPath() {
        proxied("auth.example.com", "/oauth/login", "sid=1; Domain=example.com");

        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/oauth", "sid", "1"))).isTrue();
        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/", "sid", "1"))).isFalse();
    }

    @Test
    void ignoresResponsesFromHostsOutsideTheCookieDomain() {
        proxied("notexample.com", "/", "sid=1; Domain=example.com; Path=/");

        assertThat(origins.setForWholeDomain(JarCookie.session("example.com", "/", "sid", "1"))).isFalse();
    }

    private void proxied(String host, String path, String... setCookies) {
        HttpRequest request = mock(HttpRequest.class);
        when(request.pathWithoutQuery()).thenReturn(path);
        HttpResponse response = mock(HttpResponse.class);
        List<HttpHeader> headers = Stream.of(setCookies).map(ProxyHistoryCookieOriginsTest::setCookie).toList();
        when(response.headers()).thenReturn(headers);
        ProxyHttpRequestResponse item = mock(ProxyHttpRequestResponse.class);
        HttpService service = mock(HttpService.class);
        when(service.host()).thenReturn(host);
        when(item.httpService()).thenReturn(service);
        when(item.hasResponse()).thenReturn(true);
        when(item.finalRequest()).thenReturn(request);
        when(item.response()).thenReturn(response);
        history.add(item);
    }

    private static HttpHeader setCookie(String value) {
        HttpHeader header = mock(HttpHeader.class);
        when(header.name()).thenReturn("Set-Cookie");
        when(header.value()).thenReturn(value);
        return header;
    }
}
