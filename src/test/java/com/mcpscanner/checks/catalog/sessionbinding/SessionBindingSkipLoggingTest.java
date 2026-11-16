package com.mcpscanner.checks.catalog.sessionbinding;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.crossidentity.FakeMcpTarget;
import com.mcpscanner.checks.api.crossidentity.FakeReply;
import com.mcpscanner.checks.api.crossidentity.FakeServers;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.function.Function;

import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.toolCall;
import static com.mcpscanner.checks.catalog.sessionbinding.SessionBindingHarness.withPeerB;
import static org.assertj.core.api.Assertions.assertThat;

class SessionBindingSkipLoggingTest {

    private static final String PREFIX = "Scan check: session-binding — ";
    private static final String RECORD_AT = "tools/call read_session_record at https://example.test:443/mcp";
    private static final HttpRequest SESSION_RECORD =
            toolCall("read_session_record", "{}", "A").withAddedHeader("Mcp-Session-Id", "sess-A");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void aRequestThatIsNotAToolCallOrResourceReadIsSkippedAsNotApplicable() {
        var run = withPeerB().run(FakeServers.sessions(true), FakeMcpTarget.request(
                "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/list\"}", "A").withAddedHeader("Mcp-Session-Id", "sess-A"));

        assertThat(run.infoLines()).containsExactly(PREFIX + "skipped tools/list at https://example.test:443/mcp "
                + "(not applicable: only tools/call and resources/read requests with a JSON-RPC id are replayed)");
    }

    @Test
    void aSessionlessRequestIsSkippedAsNotApplicable() {
        var run = withPeerB().run(FakeServers.objectStore(true), toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.infoLines()).containsExactly(PREFIX + "skipped tools/call get_note at https://example.test:443/mcp "
                + "(not applicable: the server issues no Mcp-Session-Id)");
    }

    @Test
    void anUnconfirmedWriteReplayIsSkippedAsAMissingPrerequisite() {
        var run = withPeerB().permitting(item -> false).run(FakeServers.sessions(true), SESSION_RECORD);

        assertThat(run.infoLines()).containsExactly(PREFIX + "skipped " + RECORD_AT
                + " (prerequisite missing: replaying this write operation was not confirmed)");
    }

    @Test
    void noComparedIdentityIsSkippedAsAMissingPrerequisite() {
        var run = new SessionBindingHarness().run(FakeServers.sessions(true), SESSION_RECORD);

        assertThat(run.infoLines()).containsExactly(PREFIX + "skipped " + RECORD_AT
                + " (prerequisite missing: no compared identities with credentials)");
    }

    @Test
    void anOwnerInitializeTheServerRefusesIsNotLoggedAsAStatelessServer() {
        Function<HttpRequest, FakeReply> sessions = FakeServers.sessions(true);
        var run = withPeerB().run(request -> "initialize".equals(FakeMcpTarget.method(request))
                ? FakeReply.unauthorized() : sessions.apply(request),
                toolCall("read_session_record", "{}", "A"));

        assertThat(run.infoLines()).containsExactly(PREFIX + "stopped " + RECORD_AT
                + " (transport failure: the owner's initialize was refused or got no reply, "
                + "so no probe session could be opened)");
        assertThat(run.decisions()).containsOnly("session_binding:owner_initialize_failed");
    }

    @Test
    void aSessionIssuedToTheOwnerIsDeletedEvenWhenJoiningItThrows() {
        Function<HttpRequest, FakeReply> sessions = FakeServers.sessions(true);
        var run = withPeerB().run(request -> {
            if ("notifications/initialized".equals(FakeMcpTarget.method(request))) {
                throw new IllegalStateException("connection reset");
            }
            return sessions.apply(request);
        }, toolCall("read_session_record", "{}", "A"));

        assertThat(run.sent()).filteredOn(request -> "DELETE".equals(request.method())).isNotEmpty();
    }

    @Test
    void aHostWhoseIdentitiesAreAllClaimedIsSkippedAsAlreadyAudited() {
        var harness = withPeerB().against(FakeServers.sessions(true));
        harness.audit(SESSION_RECORD);
        harness.audit(SESSION_RECORD);

        assertThat(harness.infoLines()).contains(PREFIX + "skipped " + RECORD_AT
                + " (already audited on this connection: every compared identity was already probed on this host)");
    }

    @Test
    void anIdentityThatGetsTheOwnersResultInItsOwnSessionIsSkipped() {
        var run = withPeerB().run(request -> FakeMcpTarget.principal(request) == null ? FakeReply.unauthorized()
                : "initialize".equals(FakeMcpTarget.method(request)) ? FakeReply.initialized("sess-X")
                : FakeReply.result("docs"), SESSION_RECORD);

        assertThat(run.infoLines()).contains(PREFIX + "skipped " + RECORD_AT
                + " as identity-B (not applicable: the identity's own session already gets the owner's result)");
    }

    @Test
    void aServerThatRebindsSessionsSkipsTheLiveSessionBinding() {
        var run = withPeerB().run(FakeServers.rebindingSessions(false), SESSION_RECORD);

        assertThat(run.infoLines()).contains(PREFIX + "skipped " + RECORD_AT + " as identity-B (not applicable: "
                + "the server rebinds a session to the presented credential, so the live session is not probed)");
    }

    @Test
    void aDisturbedTrialSessionSkipsTheLiveSessionBinding() {
        var run = withPeerB().run(FakeServers.terminatingSessions(false), SESSION_RECORD);

        assertThat(run.infoLines()).contains(PREFIX + "skipped " + RECORD_AT + " as identity-B (not applicable: "
                + "the trial disturbed the owner's disposable session, so the live session is not probed)");
    }

    @Test
    void anOwnerCallThatFailsInAFreshSessionSkipsTheIdentity() {
        Function<HttpRequest, FakeReply> sessions = FakeServers.sessions(true);
        var run = withPeerB().run(request -> "tools/call".equals(FakeMcpTarget.method(request))
                && !"sess-A".equals(request.headerValue("Mcp-Session-Id")) ? FakeReply.unauthorized()
                : sessions.apply(request), SESSION_RECORD);

        assertThat(run.infoLines()).contains(PREFIX + "skipped " + RECORD_AT
                + " as identity-B (prerequisite missing: the owner's call failed in a fresh session)");
    }

    @Test
    void aSessionlessRequestWhoseFreshSessionHoldsNoRecordIsSkippedWithTheReason() {
        Function<HttpRequest, FakeReply> sessions = FakeServers.sessions(false);
        var run = withPeerB().run(request -> "tools/call".equals(FakeMcpTarget.method(request))
                ? FakeReply.result("") : sessions.apply(request), toolCall("read_session_record", "{}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.infoLines()).contains(PREFIX + "skipped " + RECORD_AT
                + " (prerequisite missing: the owner's request returned an empty result)");
    }

    @Test
    void aRateLimitedIdentityStopsItsProbes() {
        Function<HttpRequest, FakeReply> sessions = FakeServers.sessions(true);
        var run = withPeerB().run(request -> "B".equals(FakeMcpTarget.principal(request))
                ? new FakeReply(429, "", Map.of()) : sessions.apply(request), SESSION_RECORD);

        assertThat(run.infoLines()).filteredOn(line -> line.contains("skipped ") || line.contains("stopped "))
                .containsExactly(PREFIX + "stopped " + RECORD_AT
                        + " as identity-B (rate limited: the server answered HTTP 429)");
    }
}
