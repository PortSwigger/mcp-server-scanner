package com.mcpscanner.signedin;

import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Stream;

public final class ProxyHistoryCookieOrigins implements CookieOrigins {

    private static final String SET_COOKIE = "Set-Cookie";
    private static final String ROOT = "/";

    private final Function<ProxyHistoryFilter, List<ProxyHttpRequestResponse>> history;

    public ProxyHistoryCookieOrigins(Function<ProxyHistoryFilter, List<ProxyHttpRequestResponse>> history) {
        this.history = history;
    }

    @Override
    public boolean setForWholeDomain(Cookie jarCookie) {
        String domain = lowerCase(jarCookie.domain());
        return history.apply(item -> item.hasResponse() && within(hostOf(item), domain)).stream()
                .flatMap(item -> producing(item, jarCookie, domain))
                .reduce((earlier, later) -> later)
                .map(setCookie -> setCookie.domain().isPresent())
                .orElse(false);
    }

    private static Stream<SetCookie> producing(ProxyHttpRequestResponse item, Cookie jarCookie, String domain) {
        String requestPath = item.finalRequest().pathWithoutQuery();
        return item.response().headers().stream()
                .filter(header -> SET_COOKIE.equalsIgnoreCase(header.name()))
                .flatMap(header -> SetCookie.parse(header.value(), requestPath).stream())
                .filter(setCookie -> setCookie.name().equals(jarCookie.name())
                        && setCookie.value().equals(jarCookie.value())
                        && setCookie.domainFor(hostOf(item)).equals(domain)
                        && setCookie.path().equals(pathOf(jarCookie)));
    }

    private static String hostOf(ProxyHttpRequestResponse item) {
        return lowerCase(item.httpService().host());
    }

    private static boolean within(String host, String domain) {
        return host.equals(domain) || host.endsWith("." + domain);
    }

    private static String pathOf(Cookie jarCookie) {
        String path = jarCookie.path();
        return path == null || path.isEmpty() ? ROOT : path;
    }

    private static String lowerCase(String value) {
        return Objects.requireNonNullElse(value, "").toLowerCase(Locale.ROOT);
    }
}
