package com.mcpscanner.checks.shared.oauth;

import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.html;
import static com.mcpscanner.checks.shared.oauth.ScriptedHttp.redirect;
import static org.assertj.core.api.Assertions.assertThat;

class SameOriginRedirectsTest {

    private static final String ORIGIN = "https://as.example";
    private static final URI START = URI.create(ORIGIN + "/authorize?x=1");
    private static final String CALLBACK = "http://127.0.0.1:49151/cb";

    private ScriptedHttp server;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        server = new ScriptedHttp();
    }

    private Optional<RedirectTrail> follow(SameOriginRedirects redirects) {
        return redirects.follow(START, location -> location.toString().startsWith(CALLBACK));
    }

    @Test
    void followsRelativeSameOriginRedirectsToTheFinalPage() {
        server.on("GET", ORIGIN + "/authorize", redirect("/login"))
                .on("GET", ORIGIN + "/login", html("<form></form>"));

        RedirectTrail trail = follow(SameOriginRedirects.withoutCookies(server.oauth(), 3)).orElseThrow();

        assertThat(trail.exchanges()).hasSize(2);
        assertThat(trail.lastRequested()).isEqualTo(URI.create(ORIGIN + "/login"));
        assertThat(trail.stoppedAt()).isEmpty();
    }

    @Test
    void stopsWithoutRequestingALocationTheCallerIsWaitingFor() {
        server.on("GET", ORIGIN + "/authorize", redirect(CALLBACK + "?code=c"));

        RedirectTrail trail = follow(SameOriginRedirects.withoutCookies(server.oauth(), 3)).orElseThrow();

        assertThat(trail.stoppedAt()).contains(URI.create(CALLBACK + "?code=c"));
        assertThat(server.sentUrls()).containsExactly(START.toString());
    }

    @Test
    void neverFollowsAnotherOrigin() {
        server.on("GET", ORIGIN + "/authorize", redirect("https://idp.example/authorize"));

        RedirectTrail trail = follow(SameOriginRedirects.withoutCookies(server.oauth(), 3)).orElseThrow();

        assertThat(trail.stoppedAt()).isEmpty();
        assertThat(server.sentUrls()).containsExactly(START.toString());
    }

    @Test
    void followsAtMostTheGivenNumberOfRedirects() {
        server.on("GET", ORIGIN + "/authorize", redirect(ORIGIN + "/authorize?again=1"));

        RedirectTrail trail = follow(SameOriginRedirects.withoutCookies(server.oauth(), 2)).orElseThrow();

        assertThat(server.sentUrls()).hasSize(3);
        assertThat(trail.hopLimitReached()).isTrue();
    }

    @Test
    void aTrailEndingOnAPageDidNotReachTheHopLimit() {
        server.on("GET", ORIGIN + "/authorize", redirect("/login"))
                .on("GET", ORIGIN + "/login", html("<form></form>"));

        assertThat(follow(SameOriginRedirects.withoutCookies(server.oauth(), 1)).orElseThrow().hopLimitReached())
                .isFalse();
    }

    @Test
    void anUnansweredRequestEndsTheTrailWithNothing() {
        server.on("GET", ORIGIN + "/authorize", ScriptedHttp.NO_RESPONSE);

        assertThat(follow(SameOriginRedirects.withoutCookies(server.oauth(), 3))).isEmpty();
    }

    @Test
    void carriesTheCookiesItWasGivenOnlyWhenAsked() {
        server.on("GET", ORIGIN + "/authorize", request -> "sid=new".equals(request.headerValue("Cookie"))
                        ? redirect(CALLBACK + "?code=c")
                        : "HTTP/1.1 302 Found\r\nSet-Cookie: sid=new; Path=/; HttpOnly\r\nLocation: /authorize?again=1\r\n\r\n");

        RedirectTrail carried = follow(SameOriginRedirects.carryingCookies(server.oauth(), 3)).orElseThrow();
        RedirectTrail uncarried = follow(SameOriginRedirects.withoutCookies(server.oauth(), 3)).orElseThrow();

        assertThat(carried.stoppedAt()).isPresent();
        assertThat(carried.sessionCreatedBy()).contains(URI.create(ORIGIN + "/authorize"));
        assertThat(uncarried.stoppedAt()).isEmpty();
        assertThat(uncarried.sessionCreatedBy()).isEmpty();
    }

    @Test
    void aTrailThatCarriedNoCookieCreatedNoSession() {
        server.on("GET", ORIGIN + "/authorize", "HTTP/1.1 302 Found\r\nSet-Cookie: sid=x\r\nLocation: " + CALLBACK
                + "?code=c\r\n\r\n");

        assertThat(follow(SameOriginRedirects.carryingCookies(server.oauth(), 3)).orElseThrow().sessionCreatedBy())
                .isEmpty();
    }

    @Test
    void seedsTheInitialCookiesAndAddsTheOnesSetAlongTheWay() {
        server.on("GET", ORIGIN + "/authorize", "HTTP/1.1 302 Found\r\nSet-Cookie: csrf=t1; Path=/\r\n"
                        + "Location: /consent\r\n\r\n")
                .on("GET", ORIGIN + "/consent", html("<form></form>"));

        follow(SameOriginRedirects.carryingCookies(server.oauth(), 3, List.of(new SessionCookie("sid", "alice", "/"))));

        assertThat(server.sentTo(ORIGIN + "/authorize")).singleElement()
                .satisfies(request -> assertThat(request.headerValue("Cookie")).isEqualTo("sid=alice"));
        assertThat(server.sentTo(ORIGIN + "/consent")).singleElement()
                .satisfies(request -> assertThat(request.headerValue("Cookie")).isEqualTo("sid=alice; csrf=t1"));
    }

    @Test
    void aJarCookieGoesOnlyToTheHopsWithinItsPath() {
        server.on("GET", ORIGIN + "/authorize", redirect("/login"))
                .on("GET", ORIGIN + "/login", html("<form></form>"));

        follow(SameOriginRedirects.carryingCookies(server.oauth(), 3, List.of(
                new SessionCookie("scoped", "1", "/authorize"), new SessionCookie("site", "2", "/"))));

        assertThat(server.sentTo(ORIGIN + "/authorize")).singleElement()
                .satisfies(request -> assertThat(request.headerValue("Cookie")).isEqualTo("scoped=1; site=2"));
        assertThat(server.sentTo(ORIGIN + "/login")).singleElement()
                .satisfies(request -> assertThat(request.headerValue("Cookie")).isEqualTo("site=2"));
    }

    @Test
    void theMostSpecificPathWinsWhenTwoJarCookiesShareAName() {
        server.on("GET", ORIGIN + "/authorize", html("<form></form>"));

        follow(SameOriginRedirects.carryingCookies(server.oauth(), 3, List.of(
                new SessionCookie("sid", "root", "/"), new SessionCookie("sid", "scoped", "/authorize"))));

        assertThat(server.sentTo(ORIGIN + "/authorize")).singleElement()
                .satisfies(request -> assertThat(request.headerValue("Cookie")).isEqualTo("sid=scoped"));
    }
}
