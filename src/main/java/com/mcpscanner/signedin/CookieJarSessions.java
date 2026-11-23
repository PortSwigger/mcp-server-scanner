package com.mcpscanner.signedin;

import burp.api.montoya.http.message.Cookie;
import com.mcpscanner.checks.api.SignedInSession;
import com.mcpscanner.checks.shared.oauth.SessionCookie;

import java.net.URI;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

public final class CookieJarSessions {

    static final String SOURCE = "Burp's cookie jar";

    private final Supplier<List<Cookie>> jar;
    private final CookieOrigins origins;
    private final Clock clock;

    public CookieJarSessions(Supplier<List<Cookie>> jar, CookieOrigins origins, Clock clock) {
        this.jar = jar;
        this.origins = origins;
        this.clock = clock;
    }

    public Optional<SignedInSession> sessionFor(URI endpoint) {
        CookieScope scope = CookieScope.of(endpoint);
        List<SessionCookie> cookies = jar.get().stream()
                .filter(cookie -> scope.sendsToHost(cookie, clock.instant(), origins))
                .map(cookie -> new SessionCookie(cookie.name(), cookie.value(), cookie.path()))
                .toList();
        boolean appliesToEndpoint = cookies.stream().anyMatch(cookie -> scope.appliesToEndpoint(cookie.path()));
        return appliesToEndpoint ? Optional.of(new SignedInSession(cookies, SOURCE)) : Optional.empty();
    }
}
