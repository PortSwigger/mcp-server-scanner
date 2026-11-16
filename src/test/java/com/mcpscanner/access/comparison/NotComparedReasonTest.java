package com.mcpscanner.access.comparison;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.crossidentity.FakeReply;
import com.mcpscanner.checks.api.crossidentity.FakeServers;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.function.Function;

import static com.mcpscanner.access.comparison.ComparisonHarness.withPeerB;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.principal;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.toolCall;
import static org.assertj.core.api.Assertions.assertThat;

class NotComparedReasonTest {

    private static final HttpRequest GET_NOTE = toolCall("get_note", "{\"id\":\"a1\"}", "A");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void anOwnerJsonRpcErrorIsTheReasonInTheLedgerAndTheLogLine() {
        var run = withPeerB().run(owner(FakeReply.rpcError(-32602,
                "provided parameters were invalid: parameter \\\"sql\\\" is required")), GET_NOTE);

        String reason = run.ledger().notCompared().orElseThrow();
        assertThat(reason).endsWith("'s own call returned a JSON-RPC error: provided parameters were invalid: "
                + "parameter \"sql\" is required");
        assertThat(run.ledger().outcomes()).containsEntry("b", AccessOutcome.NOT_RUN);
        assertThat(run.infoLines()).singleElement().asString()
                .startsWith("Check access — tools/call get_note: not compared: " + reason + "; outcomes ");
    }

    @Test
    void anOwnerToolErrorIsTheReason() {
        var run = withPeerB().run(owner(FakeReply.toolError("sql parameter cannot be empty")), GET_NOTE);

        assertThat(run.ledger().notCompared()).hasValueSatisfying(reason ->
                assertThat(reason).endsWith("'s own call returned isError: sql parameter cannot be empty"));
    }

    @Test
    void anUnansweredAnonymousCallSaysSo() {
        var run = withPeerB().run(request -> principal(request) == null ? new FakeReply(429, "", Map.of())
                : FakeServers.objectStore(true).apply(request), GET_NOTE);

        assertThat(run.ledger().notCompared())
                .contains("the call without credentials got no response, so there is nothing to compare against");
    }

    @Test
    void anAnonymousCallGettingTheOwnersResultSaysSo() {
        var run = withPeerB().run(FakeServers.open(), GET_NOTE);

        assertThat(run.ledger().notCompared()).hasValueSatisfying(reason ->
                assertThat(reason).startsWith("Anonymous already gets ").endsWith("'s result, so anyone can reach it"));
    }

    @Test
    void aComparedItemHasNoReason() {
        var run = withPeerB().run(FakeServers.objectStore(true), GET_NOTE);

        assertThat(run.ledger().notCompared()).isEmpty();
    }

    private static Function<HttpRequest, FakeReply> owner(FakeReply ownerReply) {
        return request -> "A".equals(principal(request)) ? ownerReply : FakeServers.objectStore(true).apply(request);
    }
}
