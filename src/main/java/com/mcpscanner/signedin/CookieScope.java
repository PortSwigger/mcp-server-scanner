package com.mcpscanner.signedin;

import burp.api.montoya.http.message.Cookie;
import com.mcpscanner.checks.shared.oauth.CookiePath;

import java.net.URI;
import java.time.Instant;
import java.util.Locale;

record CookieScope(String host, String path) {

    private static final String DOMAIN_COOKIE_MARK = ".";

    static CookieScope of(URI endpoint) {
        return new CookieScope(lowerCase(endpoint.getHost()), endpoint.getRawPath());
    }

    boolean sendsToHost(Cookie cookie, Instant now, CookieOrigins origins) {
        return unexpired(cookie, now) && domainMatches(cookie, origins);
    }

    boolean appliesToEndpoint(String cookiePath) {
        return CookiePath.admits(cookiePath, path);
    }

    private boolean domainMatches(Cookie cookie, CookieOrigins origins) {
        String cookieDomain = lowerCase(cookie.domain());
        if (cookieDomain.startsWith(DOMAIN_COOKIE_MARK)) {
            return covers(cookieDomain.substring(DOMAIN_COOKIE_MARK.length()));
        }
        return host.equals(cookieDomain) || covers(cookieDomain) && origins.setForWholeDomain(cookie);
    }

    private boolean covers(String domain) {
        return !domain.isEmpty() && (host.equals(domain) || host.endsWith(DOMAIN_COOKIE_MARK + domain));
    }

    private static boolean unexpired(Cookie cookie, Instant now) {
        return cookie.expiration().map(expiry -> expiry.toInstant().isAfter(now)).orElse(true);
    }

    private static String lowerCase(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }
}
