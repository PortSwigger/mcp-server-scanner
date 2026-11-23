package com.mcpscanner.checks.shared.oauth;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

public final class SameOriginRedirects {

    private static final String BROWSER_ACCEPT = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8";

    private final OAuthHttp http;
    private final int maxRedirects;
    private final boolean carryCookies;
    private final List<SessionCookie> initialCookies;

    private SameOriginRedirects(OAuthHttp http, int maxRedirects, boolean carryCookies,
                                List<SessionCookie> initialCookies) {
        this.http = http;
        this.maxRedirects = maxRedirects;
        this.carryCookies = carryCookies;
        this.initialCookies = List.copyOf(initialCookies);
    }

    public static SameOriginRedirects withoutCookies(OAuthHttp http, int maxRedirects) {
        return new SameOriginRedirects(http, maxRedirects, false, List.of());
    }

    public static SameOriginRedirects carryingCookies(OAuthHttp http, int maxRedirects) {
        return carryingCookies(http, maxRedirects, List.of());
    }

    public static SameOriginRedirects carryingCookies(OAuthHttp http, int maxRedirects,
                                                      List<SessionCookie> initialCookies) {
        return new SameOriginRedirects(http, maxRedirects, true, initialCookies);
    }

    public Optional<RedirectTrail> follow(URI start, Predicate<URI> stopAt) {
        List<HttpRequestResponse> exchanges = new ArrayList<>();
        CookieJar cookies = new CookieJar(initialCookies);
        URI current = start;
        while (true) {
            Optional<HttpRequestResponse> exchange = http.get(current, BROWSER_ACCEPT, cookieHeader(cookies, current));
            if (exchange.isEmpty()) {
                return Optional.empty();
            }
            exchanges.add(exchange.get());
            cookies.collect(exchange.get().response());
            Optional<URI> location = redirectTarget(current, exchange.get());
            if (location.isPresent() && stopAt.test(location.get())) {
                return Optional.of(new RedirectTrail(exchanges, current, location, false));
            }
            if (location.isEmpty() || !HttpUris.sameOrigin(start, location.get())) {
                return Optional.of(new RedirectTrail(exchanges, current, Optional.empty(), false));
            }
            if (exchanges.size() > maxRedirects) {
                return Optional.of(new RedirectTrail(exchanges, current, Optional.empty(), true));
            }
            current = location.get();
        }
    }

    private Map<String, String> cookieHeader(CookieJar cookies, URI target) {
        return carryCookies ? cookies.header(target) : Map.of();
    }

    private static Optional<URI> redirectTarget(URI from, HttpRequestResponse exchange) {
        if (!RedirectStatus.isRedirect(exchange.response().statusCode())) {
            return Optional.empty();
        }
        return ResponseHeaders.first(exchange.response(), "Location").flatMap(location -> HttpUris.resolve(from, location));
    }
}
