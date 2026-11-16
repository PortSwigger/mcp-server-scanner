package com.mcpscanner.checks.api.crossidentity;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.session.SessionHeaders;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class OpenedSessionsTest {

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void deletesEveryRecordedSessionWithTheCredentialsItWasOpenedWith() {
        FakeMcpTarget target = new FakeMcpTarget(request -> FakeReply.result("ok"));
        OpenedSessions sessions = new OpenedSessions();
        sessions.record(SessionHeaders.inSession(FakeMcpTarget.toolCall("t", "{}", "B"), "probe-b"));
        sessions.record(SessionHeaders.inSession(FakeMcpTarget.toolCall("t", "{}", "A"), "probe-a"));

        sessions.deleteAll(target.http(), Optional.empty());

        assertThat(target.sent()).extracting(HttpRequest::method).containsExactly("DELETE", "DELETE");
        assertThat(target.sent()).extracting(request -> request.headerValue("Mcp-Session-Id"))
                .containsExactly("probe-b", "probe-a");
        assertThat(target.sent()).extracting(FakeMcpTarget::principal).containsExactly("B", "A");
        assertThat(target.sent()).allSatisfy(request -> assertThat(request.bodyToString()).isEmpty());
    }

    @Test
    void neverDeletesTheProtectedLiveSessionAndDeletesEachSessionOnce() {
        FakeMcpTarget target = new FakeMcpTarget(request -> FakeReply.result("ok"));
        OpenedSessions sessions = new OpenedSessions();
        sessions.record(SessionHeaders.inSession(FakeMcpTarget.toolCall("t", "{}", "A"), "live"));
        sessions.record(SessionHeaders.inSession(FakeMcpTarget.toolCall("t", "{}", "B"), "probe"));
        sessions.record(SessionHeaders.inSession(FakeMcpTarget.toolCall("t", "{}", "B"), "probe"));

        sessions.deleteAll(target.http(), Optional.of("live"));
        sessions.deleteAll(target.http(), Optional.of("live"));

        assertThat(target.sent()).extracting(request -> request.headerValue("Mcp-Session-Id"))
                .containsExactly("probe");
    }

    @Test
    void aFailingDeleteDoesNotStopTheOthers() {
        FakeMcpTarget target = new FakeMcpTarget(request -> {
            if ("first".equals(request.headerValue("Mcp-Session-Id"))) {
                throw new IllegalStateException("unreachable");
            }
            return FakeReply.result("ok");
        });
        OpenedSessions sessions = new OpenedSessions();
        sessions.record(SessionHeaders.inSession(FakeMcpTarget.toolCall("t", "{}", "B"), "first"));
        sessions.record(SessionHeaders.inSession(FakeMcpTarget.toolCall("t", "{}", "B"), "second"));

        sessions.deleteAll(target.http(), Optional.empty());

        assertThat(target.sent()).extracting(request -> request.headerValue("Mcp-Session-Id"))
                .containsExactly("first", "second");
    }

    @Test
    void sendsEachDeleteStraightToTheTargetWithoutTheSentinelsThatRouteItThroughTheLocalProxy() {
        FakeMcpTarget target = new FakeMcpTarget(request -> FakeReply.result("ok"));
        OpenedSessions sessions = new OpenedSessions();
        sessions.record(SessionHeaders.inSession(FakeMcpTarget.toolCall("t", "{}", "B")
                .withHeader(ScannerSentinels.IDENTITY_HEADER, "b")
                .withHeader(ScannerSentinels.STRIP_AUTH_HEADER, ScannerSentinels.SENTINEL_VALUE), "probe"));

        sessions.deleteAll(target.http(), Optional.empty());

        assertThat(target.sent()).singleElement().satisfies(delete -> {
            assertThat(delete.headerValue(ScannerSentinels.DIRECT_DELIVERY_HEADER))
                    .isEqualTo(ScannerSentinels.SENTINEL_VALUE);
            assertThat(delete.headers()).noneMatch(header -> ScannerSentinels.ROUTES_TO_PROXY.contains(header.name()));
            assertThat(FakeMcpTarget.principal(delete)).isEqualTo("B");
        });
    }
}
