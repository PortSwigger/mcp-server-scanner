package com.mcpscanner.checks.shared.auth.oracle;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static com.mcpscanner.checks.shared.auth.oracle.Exchanges.SECRET_RESULT;
import static com.mcpscanner.checks.shared.auth.oracle.Exchanges.exchange;
import static com.mcpscanner.checks.shared.auth.oracle.Exchanges.notification;
import static com.mcpscanner.checks.shared.auth.oracle.Exchanges.toolCall;
import static com.mcpscanner.checks.shared.auth.oracle.Exchanges.toolCallSse;
import static org.assertj.core.api.Assertions.assertThat;

class BaselineEquivalenceOracleTest {

    private static final String RPC_UNAUTHORIZED =
            "{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32001,\"message\":\"Unauthorized\"}}";

    private final BaselineEquivalenceOracle oracle = BaselineEquivalenceOracle.defaultOracle();

    private HttpRequestResponse baseline;
    private List<HttpRequestResponse> refusedControls;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        baseline = toolCall(200, SECRET_RESULT);
        refusedControls = List.of(toolCall(401, "{\"error\":\"unauthorized\"}"), toolCall(200, RPC_UNAUTHORIZED));
    }

    private OracleVerdict judge(HttpRequestResponse candidate) {
        return oracle.judge(new OracleEvidence(baseline, refusedControls, candidate));
    }

    @Test
    void sameResultAsBaselineWhileControlsAreRefusedIsAHit() {
        assertThat(judge(toolCall(200, SECRET_RESULT))).isEqualTo(OracleVerdict.HIT);
        assertThat(judge(toolCall(200, SECRET_RESULT)).isHit()).isTrue();
    }

    @Test
    void defaultOracleRequiresTheSameOperationPayloadValue() {
        String sameShape = SECRET_RESULT.replace("s3cr3t", "Please connect your account first");

        assertThat(judge(toolCall(200, sameShape))).isEqualTo(OracleVerdict.CANDIDATE_NOT_EQUIVALENT);
        assertThat(new BaselineEquivalenceOracle(new SameResultShape())
                .judge(new OracleEvidence(baseline, refusedControls, toolCall(200, sameShape))))
                .isEqualTo(OracleVerdict.HIT);
    }

    @Test
    void defaultOracleComparesNonOperationResultsByShape() {
        String catalog = "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[{\"name\":\"a\"}]}}";
        baseline = toolCall(200, catalog);

        assertThat(judge(toolCall(200, catalog.replace("\"a\"", "\"b\"")))).isEqualTo(OracleVerdict.HIT);
    }

    @Test
    void aDifferentResultShapeIsNotAHit() {
        String catalog = "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[{\"name\":\"a\"}]}}";

        assertThat(judge(toolCall(200, catalog))).isEqualTo(OracleVerdict.CANDIDATE_NOT_EQUIVALENT);
    }

    @Nested
    class Baseline {

        @ParameterizedTest
        @ValueSource(ints = {401, 403, 500, 302})
        void deniedOrFailedBaselineNeverHits(int status) {
            baseline = toolCall(status, SECRET_RESULT);

            assertThat(judge(toolCall(200, SECRET_RESULT))).isEqualTo(OracleVerdict.BASELINE_NOT_SUCCESSFUL);
        }

        @Test
        void jsonRpcErrorBaselineNeverHits() {
            baseline = toolCall(200, RPC_UNAUTHORIZED);

            assertThat(judge(toolCall(200, SECRET_RESULT))).isEqualTo(OracleVerdict.BASELINE_NOT_SUCCESSFUL);
        }

        @Test
        void unansweredBaselineNeverHits() {
            baseline = Exchanges.unanswered();

            assertThat(judge(toolCall(200, SECRET_RESULT))).isEqualTo(OracleVerdict.BASELINE_NOT_SUCCESSFUL);
        }
    }

    @Nested
    class Controls {

        @Test
        void noControlsMeansNoHit() {
            refusedControls = List.of();

            assertThat(judge(toolCall(200, SECRET_RESULT))).isEqualTo(OracleVerdict.NO_REFUSAL_CONTROLS);
        }

        @Test
        void aControlThatSucceedsMeansNoHit() {
            refusedControls = List.of(toolCall(401, ""), toolCall(200, SECRET_RESULT));

            assertThat(judge(toolCall(200, SECRET_RESULT))).isEqualTo(OracleVerdict.CONTROL_NOT_REFUSED);
        }

        @Test
        void aControlWithNoResponseIsNotProofOfRefusal() {
            refusedControls = List.of(toolCall(401, ""), Exchanges.unanswered());

            assertThat(judge(toolCall(200, SECRET_RESULT))).isEqualTo(OracleVerdict.CONTROL_NOT_REFUSED);
        }

        @Test
        void aChunkFramedPlainTextRefusalCountsAsRefused() {
            refusedControls = List.of(Exchanges.exchange(Exchanges.TOOL_CALL, 200,
                    "text/plain\r\nTransfer-Encoding: chunked", "5\r\nUnaut\r\n7\r\nhorized\r\n0\r\n\r\n"));

            assertThat(judge(toolCall(200, SECRET_RESULT))).isEqualTo(OracleVerdict.HIT);
        }

        @Test
        void authStatusesAndAuthRefusalBodiesCountAsRefused() {
            refusedControls = List.of(
                    toolCall(404, "Not Found"),
                    toolCall(403, ""),
                    toolCall(400, "{\"error\":\"invalid token\"}"),
                    toolCall(200, "Unauthorized"),
                    toolCall(200, "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"isError\":true,"
                            + "\"content\":[{\"type\":\"text\",\"text\":\"Forbidden\"}]}}"),
                    toolCallSse("data: " + RPC_UNAUTHORIZED + "\n\n"));

            assertThat(judge(toolCall(200, SECRET_RESULT))).isEqualTo(OracleVerdict.HIT);
        }

        @ParameterizedTest
        @ValueSource(strings = {"429|slow down", "500|boom", "502|bad gateway", "503|",
                "200|<html>Welcome</html>",
                "200|{\"jsonrpc\":\"2.0\",\"id\":57,\"result\":{\"content\":[]}}",
                "200|{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32602,\"message\":\"Invalid params\"}}",
                "200|{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[],\"isError\":true}}"})
        void nonAuthFailuresAndUnmatchedRepliesAreNotProofOfRefusal(String statusAndBody) {
            String[] parts = statusAndBody.split("\\|", 2);
            refusedControls = List.of(toolCall(401, ""), toolCall(Integer.parseInt(parts[0]), parts[1]));

            assertThat(judge(toolCall(200, SECRET_RESULT))).isEqualTo(OracleVerdict.CONTROL_NOT_REFUSED);
        }
    }

    @Nested
    class Candidate {

        @Test
        void jsonRpcErrorIsNotAHit() {
            assertThat(judge(toolCall(200, RPC_UNAUTHORIZED))).isEqualTo(OracleVerdict.CANDIDATE_NOT_SUCCESSFUL);
        }

        @Test
        void toolErrorResultIsNotAHit() {
            String toolError = SECRET_RESULT.replace("\"isError\":false", "\"isError\":true");

            assertThat(judge(toolCall(200, toolError))).isEqualTo(OracleVerdict.CANDIDATE_NOT_SUCCESSFUL);
        }

        @ParameterizedTest
        @ValueSource(strings = {"Unauthorized", "403 Forbidden: missing scope", "Access denied.",
                "Unauthenticated.", "Login required", "Missing API key",
                "{\\\"error\\\":\\\"permission denied\\\"}", "{\\\"error\\\":{\\\"status\\\":401}}"})
        void resultWhoseContentIsARefusalIsNotAHit(String text) {
            String refusal = SECRET_RESULT.replace("s3cr3t", text);

            assertThat(judge(toolCall(200, refusal))).isEqualTo(OracleVerdict.CANDIDATE_NOT_SUCCESSFUL);
        }

        @Test
        void resultTextThatMerelyMentionsAuthorizationIsStillAHit() {
            String benign = SECRET_RESULT.replace("s3cr3t", "The authorization header guide is here");
            baseline = toolCall(200, benign);

            assertThat(judge(toolCall(200, benign))).isEqualTo(OracleVerdict.HIT);
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "{\"jsonrpc\":\"2.0\",\"id\":8,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"s\"}]}}",
                "{\"jsonrpc\":\"2.0\",\"id\":\"7\",\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"s\"}]}}",
                "{\"id\":7,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"s\"}]}}",
                "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":\"text\"}",
                "{\"jsonrpc\":\"2.0\",\"id\":7}",
                "not json"})
        void replyWithoutAMatchingJsonRpcResultIsNotAHit(String body) {
            assertThat(judge(toolCall(200, body))).isEqualTo(OracleVerdict.CANDIDATE_NOT_SUCCESSFUL);
        }

        @Test
        void numericIdsMatchByValue() {
            assertThat(judge(toolCall(200, SECRET_RESULT.replace("\"id\":7", "\"id\":7.0"))))
                    .isEqualTo(OracleVerdict.HIT);
        }

        @ParameterizedTest
        @ValueSource(ints = {401, 403, 404, 500})
        void refusedStatusIsNotAHit(int status) {
            assertThat(judge(toolCall(status, SECRET_RESULT))).isEqualTo(OracleVerdict.CANDIDATE_NOT_SUCCESSFUL);
        }

        @Test
        void unansweredIsNotAHit() {
            assertThat(judge(Exchanges.unanswered())).isEqualTo(OracleVerdict.CANDIDATE_NOT_SUCCESSFUL);
        }

        @Test
        void batchOrNonJsonRequestsAreNeverJudgedSuccessful() {
            assertThat(judge(exchange("[" + Exchanges.TOOL_CALL + "]", 200, "application/json", "[" + SECRET_RESULT + "]")))
                    .isEqualTo(OracleVerdict.CANDIDATE_NOT_SUCCESSFUL);
            assertThat(judge(exchange("tool=read_secret", 200, "application/json", SECRET_RESULT)))
                    .isEqualTo(OracleVerdict.CANDIDATE_NOT_SUCCESSFUL);
        }

        @Test
        void batchArrayReplyIsSearchedForTheMatchingId() {
            String batch = "[{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}," + SECRET_RESULT + "]";

            assertThat(judge(toolCall(200, batch))).isEqualTo(OracleVerdict.HIT);
        }
    }

    @Nested
    class ServerSentEvents {

        @Test
        void sseWrappedResultAfterAnUnrelatedNotificationIsAHit() {
            String stream = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"
                    + "event: message\nid: 2\ndata: " + SECRET_RESULT + "\n\n";

            assertThat(judge(toolCallSse(stream))).isEqualTo(OracleVerdict.HIT);
        }

        @Test
        void dataFieldsWithoutASpaceAndCrlfFramingAreRead() {
            assertThat(judge(toolCallSse("data:" + SECRET_RESULT + "\r\n\r\n"))).isEqualTo(OracleVerdict.HIT);
        }

        @Test
        void unterminatedFinalEventIsRead() {
            assertThat(judge(toolCallSse("data: " + SECRET_RESULT))).isEqualTo(OracleVerdict.HIT);
        }

        @Test
        void sseWrappedErrorIsNotAHit() {
            assertThat(judge(toolCallSse("data: " + RPC_UNAUTHORIZED + "\n\n")))
                    .isEqualTo(OracleVerdict.CANDIDATE_NOT_SUCCESSFUL);
        }

        @Test
        void sseWrappedBaselineAndControlsAreReadToo() {
            baseline = toolCallSse("data: " + SECRET_RESULT + "\n\n");
            refusedControls = List.of(toolCallSse("data: " + RPC_UNAUTHORIZED + "\n\n"));

            assertThat(judge(toolCall(200, SECRET_RESULT))).isEqualTo(OracleVerdict.HIT);
        }
    }

    @Nested
    class Notifications {

        @BeforeEach
        void notificationBaseline() {
            baseline = notification(202);
            refusedControls = List.of(notification(401), notification(403));
        }

        @Test
        void sameAcceptedStatusWhileControlsAreRefusedIsAHit() {
            assertThat(judge(notification(202))).isEqualTo(OracleVerdict.HIT);
        }

        @Test
        void differentSuccessStatusIsNotAHit() {
            assertThat(judge(notification(200))).isEqualTo(OracleVerdict.CANDIDATE_NOT_EQUIVALENT);
        }

        @Test
        void refusedCandidateIsNotAHit() {
            assertThat(judge(notification(401))).isEqualTo(OracleVerdict.CANDIDATE_NOT_SUCCESSFUL);
        }

        @Test
        void acceptedControlMeansNoHit() {
            refusedControls = List.of(notification(401), notification(202));

            assertThat(judge(notification(202))).isEqualTo(OracleVerdict.CONTROL_NOT_REFUSED);
        }

        @Test
        void refusedBaselineNeverHits() {
            baseline = notification(401);

            assertThat(judge(notification(202))).isEqualTo(OracleVerdict.BASELINE_NOT_SUCCESSFUL);
        }

        @Test
        void bodyIsIgnoredForNotifications() {
            assertThat(judge(exchange(Exchanges.NOTIFICATION, 202, "application/json", "garbage")))
                    .isEqualTo(OracleVerdict.HIT);
        }
    }

    @Nested
    class Uncontrolled {

        @Test
        void sameResultWithoutControlsIsAHit() {
            assertThat(oracle.judgeUncontrolled(baseline, toolCall(200, SECRET_RESULT))).isEqualTo(OracleVerdict.HIT);
        }

        @Test
        void differentPayloadIsNotEquivalent() {
            assertThat(oracle.judgeUncontrolled(baseline, toolCall(200, SECRET_RESULT.replace("s3cr3t", "other"))))
                    .isEqualTo(OracleVerdict.CANDIDATE_NOT_EQUIVALENT);
        }

        @Test
        void refusedCandidateIsNotSuccessful() {
            assertThat(oracle.judgeUncontrolled(baseline, toolCall(401, "{\"error\":\"unauthorized\"}")))
                    .isEqualTo(OracleVerdict.CANDIDATE_NOT_SUCCESSFUL);
        }

        @Test
        void unsuccessfulBaselineNeverHits() {
            baseline = toolCall(500, SECRET_RESULT);

            assertThat(oracle.judgeUncontrolled(baseline, toolCall(200, SECRET_RESULT)))
                    .isEqualTo(OracleVerdict.BASELINE_NOT_SUCCESSFUL);
        }

        @Test
        void notificationsCompareStatusOnly() {
            baseline = notification(202);

            assertThat(oracle.judgeUncontrolled(baseline, notification(202))).isEqualTo(OracleVerdict.HIT);
            assertThat(oracle.judgeUncontrolled(baseline, notification(200)))
                    .isEqualTo(OracleVerdict.CANDIDATE_NOT_EQUIVALENT);
        }
    }

    @Nested
    class Refusal {

        @Test
        void authStatusesAndRefusalBodiesAreRefused() {
            assertThat(oracle.refused(toolCall(401, ""))).isTrue();
            assertThat(oracle.refused(toolCall(200, RPC_UNAUTHORIZED))).isTrue();
        }

        @Test
        void successAndNonAuthFailuresAreNotRefused() {
            assertThat(oracle.refused(toolCall(200, SECRET_RESULT))).isFalse();
            assertThat(oracle.refused(toolCall(400, "{\"error\":\"Missing session\"}"))).isFalse();
            assertThat(oracle.refused(Exchanges.unanswered())).isFalse();
        }
    }

    @Nested
    class AuthenticationRefusal {

        @ParameterizedTest
        @ValueSource(strings = {
                "401|<html>Unauthorized</html>",
                "403|Forbidden",
                "403|{\"error\":\"forbidden\"}",
                "404|{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32001,\"message\":\"Session not found\"}}",
                "200|{\"jsonrpc\":\"2.0\",\"id\":7,\"error\":{\"code\":-32001,\"message\":\"Unauthorized\"}}",
                "403|{\"detail\":\"Not authenticated\"}",
                "403|",
                "403|{\"error\":\"tool forbidden for this principal\"}"
        })
        void authenticationRefusalsStayRefusals(String statusAndBody) {
            String[] parts = statusAndBody.split("\\|", 2);

            assertThat(oracle.refusedByAuthentication(toolCall(Integer.parseInt(parts[0]), parts[1]))).isTrue();
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "403|<html><body>Request blocked by the web application firewall</body></html>",
                "404|<html><body>Not Found</body></html>",
                "403|  <!DOCTYPE html><html><title>Attention Required</title></html>"
        })
        void htmlBlockPagesAreNotAuthenticationRefusals(String statusAndBody) {
            String[] parts = statusAndBody.split("\\|", 2);

            assertThat(oracle.refusedByAuthentication(toolCall(Integer.parseInt(parts[0]), parts[1]))).isFalse();
        }
    }
}
