package com.mcpscanner.access.comparison;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.access.SyntheticCall;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.FakeReply;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.function.Function;

import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.principal;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.toolCall;
import static org.assertj.core.api.Assertions.assertThat;

class SyntheticCallsTest {

    private static final String FABRICATED = "Bearer invalid_c4n4ry";
    private static final Principal FAKE_TOKEN = Principal.fakeToken(() -> Map.of("Authorization", FABRICATED));
    private static final HttpRequest LIST_USERS = toolCall("list_users", "{}", "A");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void callsAsNoCredentialAndFakeTokenWhenOnlyThePrimaryIsConfigured() {
        ComparisonHarness harness = new ComparisonHarness().synthetic(Principal.anonymous(), FAKE_TOKEN);

        var run = harness.run(onlyThePrimary(), LIST_USERS);

        assertThat(run.sent()).extracting(request -> request.headerValue("Authorization"))
                .containsExactly(null, FABRICATED);
        assertThat(run.ledger().outcomes()).containsEntry(RecordingLedger.ANONYMOUS, AccessOutcome.REFUSED)
                .containsEntry(Principal.FAKE_TOKEN_ID, AccessOutcome.REFUSED);
        assertThat(run.decisions()).contains("no_peer_profile");
    }

    @Test
    void callsAsBothEvenWhenThePrimaryIsRefusedAndRecordsWhatTheFakeTokenReached() {
        ComparisonHarness harness = new ComparisonHarness().synthetic(Principal.anonymous(), FAKE_TOKEN)
                .with(ComparisonHarness.peer("B"));

        var run = harness.run(serviceAccountForUnknownTokens(), LIST_USERS);

        assertThat(run.sent()).extracting(request -> request.headerValue("Authorization"))
                .startsWith(null, FABRICATED);
        assertThat(run.ledger().outcomes()).containsEntry(RecordingLedger.ANONYMOUS, AccessOutcome.REFUSED)
                .containsEntry(Principal.FAKE_TOKEN_ID, AccessOutcome.DIFFERENT_RESULT)
                .containsEntry("b", AccessOutcome.NOT_RUN);
    }

    @Test
    void eachSyntheticCallIsHandedOnWithItsExchange() {
        ComparisonHarness harness = new ComparisonHarness().synthetic(Principal.anonymous(), FAKE_TOKEN);

        harness.run(serviceAccountForUnknownTokens(), LIST_USERS);

        assertThat(harness.syntheticCalls()).extracting(call -> call.principal().id())
                .containsExactly(Principal.ANONYMOUS_ID, Principal.FAKE_TOKEN_ID);
        SyntheticCall fake = harness.syntheticCalls().get(1);
        assertThat(fake.item().name()).isEqualTo("list_users");
        assertThat(fake.outcome()).isEqualTo(AccessOutcome.DIFFERENT_RESULT);
        assertThat(fake.reply().exchange().request().headerValue("Authorization")).isEqualTo(FABRICATED);
        assertThat(fake.reply().exchange().response().bodyToString()).contains("alice, bob");
    }

    private static Function<HttpRequest, FakeReply> onlyThePrimary() {
        return request -> "A".equals(principal(request)) ? FakeReply.result("users: alice") : FakeReply.unauthorized();
    }

    private static Function<HttpRequest, FakeReply> serviceAccountForUnknownTokens() {
        return request -> {
            String principal = principal(request);
            if (principal == null) {
                return FakeReply.unauthorized();
            }
            return principal.startsWith("invalid_") ? FakeReply.result("users: alice, bob")
                    : FakeReply.rpcError(-32001, "forbidden");
        };
    }
}
