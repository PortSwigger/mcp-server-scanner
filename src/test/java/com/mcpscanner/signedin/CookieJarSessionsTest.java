package com.mcpscanner.signedin;

import burp.api.montoya.http.message.Cookie;
import com.mcpscanner.checks.api.SignedInSession;
import com.mcpscanner.checks.shared.oauth.SessionCookie;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CookieJarSessionsTest {

    private static final Instant NOW = Instant.parse("2026-11-18T10:00:00Z");
    private static final URI AUTHORIZE = URI.create("https://auth.example.com/oauth/authorize");

    @Test
    void sendsTheAuthorizationServerHostsCookies() {
        assertThat(sessionFrom(JarCookie.session("auth.example.com", "/", "sid", "abc")))
                .get().extracting(SignedInSession::cookies).isEqualTo(List.of(new SessionCookie("sid", "abc", "/")));
    }

    @Test
    void namesBurpsCookieJarAsTheSource() {
        assertThat(sessionFrom(JarCookie.session("auth.example.com", "/", "sid", "abc")))
                .get().extracting(SignedInSession::source).isEqualTo("Burp's cookie jar");
    }

    @Test
    void sendsAParentDomainCookieWhoseDomainIsExplicitlyDotted() {
        assertThat(sessionFrom(JarCookie.session(".example.com", "/", "dot", "1")))
                .get().extracting(SignedInSession::cookies).isEqualTo(List.of(new SessionCookie("dot", "1", "/")));
    }

    @Test
    void sendsABareParentDomainCookieOnlyWhenItWasSetForTheWholeDomain() {
        CookieOrigins origins = cookie -> cookie.name().equals("domainWide");

        assertThat(sessionFrom(origins, JarCookie.session("example.com", "/", "domainWide", "1"),
                JarCookie.session("example.com", "/", "hostOnly", "2")))
                .get().extracting(SignedInSession::cookies)
                .isEqualTo(List.of(new SessionCookie("domainWide", "1", "/")));
    }

    @Test
    void asksWhereACookieCameFromOnlyForBareParentDomainCookies() {
        List<String> asked = new java.util.ArrayList<>();
        CookieOrigins origins = cookie -> asked.add(cookie.name()) && false;

        sessionFrom(origins, JarCookie.session("auth.example.com", "/", "own", "1"),
                JarCookie.session(".example.com", "/", "dot", "2"), JarCookie.session("example.com", "/", "bare", "3"),
                JarCookie.session("other.com", "/", "foreign", "4"));

        assertThat(asked).containsExactly("bare");
    }

    @Test
    void leavesOutOtherHostsAndLookalikeDomains() {
        assertThat(sessionFrom(JarCookie.session("other.example.com", "/", "a", "1"),
                JarCookie.session("notexample.com", "/", "b", "2"),
                JarCookie.session("auth.example.com.evil", "/", "c", "3"))).isEmpty();
    }

    @Test
    void keepsEveryHostCookieWithItsPathSoEachHopSendsOnlyThoseWithinIt() {
        assertThat(sessionFrom(JarCookie.session("auth.example.com", "/oauth", "in", "1"),
                JarCookie.session("auth.example.com", "/login", "elsewhere", "2"),
                JarCookie.session("auth.example.com", "", "root", "3")))
                .get().extracting(SignedInSession::cookies).isEqualTo(List.of(new SessionCookie("in", "1", "/oauth"),
                        new SessionCookie("elsewhere", "2", "/login"), new SessionCookie("root", "3", "/")));
    }

    @Test
    void hasNoSessionWhenNoCookieAppliesToTheAuthorizationEndpoint() {
        assertThat(sessionFrom(JarCookie.session("auth.example.com", "/oauthx", "sibling", "1"),
                JarCookie.session("auth.example.com", "/admin", "elsewhere", "2"))).isEmpty();
    }

    @Test
    void leavesOutExpiredCookies() {
        ZonedDateTime now = NOW.atZone(ZoneOffset.UTC);
        assertThat(sessionFrom(JarCookie.expiringAt(now.minusSeconds(1), "auth.example.com", "old", "1"),
                JarCookie.expiringAt(now.plusHours(1), "auth.example.com", "fresh", "2")))
                .get().extracting(SignedInSession::cookies).asList().extracting("name").containsExactly("fresh");
    }

    @Test
    void matchesHostsWhateverTheirCase() {
        assertThat(sessionFrom(JarCookie.session("Auth.Example.COM", "/", "sid", "abc"))).isPresent();
    }

    @Test
    void hasNoSessionWhenTheJarHoldsNothingForTheHost() {
        assertThat(sessionFrom()).isEmpty();
    }

    private static java.util.Optional<SignedInSession> sessionFrom(Cookie... cookies) {
        return sessionFrom(cookie -> false, cookies);
    }

    private static java.util.Optional<SignedInSession> sessionFrom(CookieOrigins origins, Cookie... cookies) {
        return new CookieJarSessions(() -> List.of(cookies), origins, Clock.fixed(NOW, ZoneOffset.UTC))
                .sessionFor(AUTHORIZE);
    }
}
