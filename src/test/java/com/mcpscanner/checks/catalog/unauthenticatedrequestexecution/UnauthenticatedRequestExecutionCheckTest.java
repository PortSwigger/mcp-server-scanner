package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.shared.stream.ScriptedEventStreams;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.ConnectionScoped;
import com.mcpscanner.checks.shared.probe.SimulatedMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.mcpscanner.checks.shared.probe.SimulatedMcpServer.notification;
import static com.mcpscanner.checks.shared.probe.SimulatedMcpServer.ping;
import static com.mcpscanner.checks.shared.probe.SimulatedMcpServer.request;
import static com.mcpscanner.checks.shared.probe.SimulatedMcpServer.toolCall;
import static com.mcpscanner.checks.shared.probe.SimulatedMcpServer.toolsList;
import static org.assertj.core.api.Assertions.assertThat;

class UnauthenticatedRequestExecutionCheckTest {

    private static final String VALID_TOKEN_HEADER = SimulatedMcpServer.VALID_TOKEN;
    private static final List<String> CLIENT_ADDRESS_HEADER_NAMES =
            List.of("X-Forwarded-For", "Forwarded", "X-Real-IP", "Client-IP");
    private static final int CLIENT_ADDRESS_HEADERS = CLIENT_ADDRESS_HEADER_NAMES.size();
    private static final Map<String, String> JSON = Map.of("Content-Type", "application/json");
    private static final Map<String, String> AUTHENTICATED =
            Map.of("Content-Type", "application/json", "Authorization", SimulatedMcpServer.VALID_TOKEN);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    private static UnauthenticatedRequestExecutionCheck check(AuthStrategy strategy) {
        return new UnauthenticatedRequestExecutionCheck(McpEventLog.noop(), () -> strategy, Optional::empty,
                ScriptedEventStreams.none());
    }

    private static UnauthenticatedRequestExecutionCheck bearerCheck() {
        return check(new BearerTokenAuthStrategy("valid-token"));
    }

    private static List<AuditIssue> audit(UnauthenticatedRequestExecutionCheck check, SimulatedMcpServer server,
                                          HttpRequest seed) {
        HttpRequestResponse base = server.exchange(seed);
        return check.audit(base, server.http());
    }

    @Test
    void descriptorIsARequestCheckWithTheCatalogId() {
        assertThat(UnauthenticatedRequestExecutionDescriptor.DESCRIPTOR.id())
                .isEqualTo("unauthenticated-request-execution");
        assertThat(UnauthenticatedRequestExecutionDescriptor.DESCRIPTOR.kind()).isEqualTo(CheckKind.REQUEST);
        assertThat(bearerCheck().descriptor()).isSameAs(UnauthenticatedRequestExecutionDescriptor.DESCRIPTOR);
    }

    @Nested
    class OpenServer {

        @Test
        void operationThatIgnoresConfiguredCredentialsOnAServerThatChallengesIsMediumFirm() {
            List<AuditIssue> issues = audit(bearerCheck(), SimulatedMcpServer.open().challengingAnonymousPing(),
                    request(toolCall(), AUTHENTICATED));

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.name()).isEqualTo(FindingKind.ANONYMOUS_EXECUTION.issueName());
                assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
                assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            });
        }

        @Test
        void publicServerWithAnOptionalConfiguredKeyIsLowTentative() {
            List<AuditIssue> issues = audit(bearerCheck(), SimulatedMcpServer.open(), request(toolCall(), AUTHENTICATED));

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.name()).isEqualTo(FindingKind.ANONYMOUS_EXECUTION.issueName());
                assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
                assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            });
        }

        @Test
        void operationScannedWithoutCredentialsIsLowTentative() {
            List<AuditIssue> issues = audit(check(new NoAuthStrategy()), SimulatedMcpServer.open(),
                    request(toolCall(), JSON));

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
                assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            });
        }

        @Test
        void openCatalogIsInformation() {
            List<AuditIssue> issues = audit(bearerCheck(), SimulatedMcpServer.open(), request(toolsList(), AUTHENTICATED));

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.name()).isEqualTo(FindingKind.ANONYMOUS_CATALOG.issueName());
                assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
            });
        }

        @Test
        void openProtocolMethodsAndNotificationsAreNotReported() {
            SimulatedMcpServer server = SimulatedMcpServer.open();

            assertThat(audit(bearerCheck(), server, request(ping(), AUTHENTICATED))).isEmpty();
            assertThat(audit(bearerCheck(), server, request(notification(), AUTHENTICATED))).isEmpty();
        }

        @Test
        void statefulOpenServerIsReachedThroughAFreshAnonymousSession() {
            SimulatedMcpServer server = SimulatedMcpServer.open().requiringSessions();
            String liveSession = server.openAuthenticatedSession();
            HttpRequest seed = request(toolCall(), Map.of("Content-Type", "application/json",
                    "Authorization", SimulatedMcpServer.VALID_TOKEN, "Mcp-Session-Id", liveSession));

            List<AuditIssue> issues = audit(bearerCheck(), server, seed);

            assertThat(issues).singleElement()
                    .satisfies(issue -> assertThat(issue.name()).isEqualTo(FindingKind.ANONYMOUS_EXECUTION.issueName()));
            assertThat(server.received()).anySatisfy(sent -> {
                assertThat(sent.headerValue("Authorization")).isNull();
                assertThat(sent.bodyToString()).contains("\"initialize\"");
            });
            assertThat(issues.get(0).requestResponses()).hasSize(2).last().satisfies(anonymous -> {
                assertThat(anonymous.request().headerValue("Authorization")).isNull();
                assertThat(anonymous.request().headerValue("Mcp-Session-Id")).isNotNull().isNotEqualTo(liveSession);
            });
        }

        @Test
        void anonymousSoftRefusalWithAuthenticatedBaselineIsNotReported() {
            SimulatedMcpServer server = SimulatedMcpServer.open()
                    .answeringAnonymousCallersWith("Please connect your account first");

            assertThat(audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED))).isEmpty();
        }
    }

    @Nested
    class EnforcingServer {

        @Test
        void enforcedAuthenticationIsSilent() {
            assertThat(audit(bearerCheck(), SimulatedMcpServer.enforcing(), request(toolCall(), AUTHENTICATED))).isEmpty();
            assertThat(audit(bearerCheck(), SimulatedMcpServer.enforcing().requiringSessions(),
                    request(toolCall(), AUTHENTICATED))).isEmpty();
        }

        @Test
        void unguardedPathAliasIsAHighFirmBypassForOperations() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/MCP");

            List<AuditIssue> issues = audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED));

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.name()).isEqualTo(FindingKind.AUTHENTICATION_BYPASS.issueName());
                assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
                assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
                assertThat(issue.detail()).contains("path.case");
            });
        }

        @Test
        void throttledForwardedClientProbesLeaveTheBypassSweepRunning() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/MCP")
                    .throttlingForwardedHeaders();

            List<AuditIssue> issues = audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED));

            assertThat(issues).singleElement().satisfies(issue ->
                    assertThat(issue.name()).isEqualTo(FindingKind.AUTHENTICATION_BYPASS.issueName()));
        }

        @Test
        void trustedClientAddressHeaderIsABypass() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().trustingHeader("X-Forwarded-For");

            List<AuditIssue> issues = audit(bearerCheck(), server, request(toolsList(), AUTHENTICATED));

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.name()).isEqualTo(FindingKind.AUTHENTICATION_BYPASS.issueName());
                assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
                assertThat(issue.detail()).contains("forwarded-for");
            });
        }

        @Test
        void notificationBypassIsStatusOnlyInformation() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/MCP");

            List<AuditIssue> issues = audit(bearerCheck(), server, request(notification(), AUTHENTICATED));

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
                assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            });
        }

        @Test
        void sessionIdThatAuthenticatesIsReportedAsSessionCredential() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().requiringSessions().authenticatingBySession();
            String liveSession = server.openAuthenticatedSession();
            HttpRequest seed = request(toolCall(), Map.of("Content-Type", "application/json",
                    "Authorization", SimulatedMcpServer.VALID_TOKEN, "Mcp-Session-Id", liveSession));

            List<AuditIssue> issues = audit(bearerCheck(), server, seed);

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.name()).isEqualTo(FindingKind.SESSION_CREDENTIAL.issueName());
                assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.LOW);
                assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            });
        }

        @Test
        void sweepStaysWithinTheRequestBudget() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing();
            audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED));

            assertThat(server.received().size() - 1).isLessThanOrEqualTo(UnauthenticatedRequestExecutionCheck.REQUEST_BUDGET + 1);
        }
    }

    @Nested
    class Applicability {

        @Test
        void nonMcpRequestsAreIgnoredWithoutSendingAnything() {
            SimulatedMcpServer server = SimulatedMcpServer.open();
            HttpRequestResponse base = server.exchange(request("not json", JSON));

            assertThat(bearerCheck().audit(base, server.http())).isEmpty();
            assertThat(server.received()).hasSize(1);
        }

        @Test
        void batchRequestsAreIgnored() {
            SimulatedMcpServer server = SimulatedMcpServer.open();
            HttpRequestResponse base = server.exchange(request("[" + toolCall() + "]", JSON));

            assertThat(bearerCheck().audit(base, server.http())).isEmpty();
        }

        @Test
        void unansweredBaseRequestIsSentOnceAsTheBaseline() {
            SimulatedMcpServer server = SimulatedMcpServer.open();
            HttpRequestResponse unanswered = HttpRequestResponse.httpRequestResponse(request(toolCall(), AUTHENTICATED), null);

            assertThat(bearerCheck().audit(unanswered, server.http())).hasSize(1);
        }

        @Test
        void unsuccessfulBaselineIsSilent() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing();

            assertThat(audit(bearerCheck(), server, request(toolCall(), JSON))).isEmpty();
        }
    }

    @Test
    void successfulCapturedBaseIsUsedAsTheBaselineWithoutResending() {
        SimulatedMcpServer server = SimulatedMcpServer.open();
        HttpRequestResponse base = server.exchange(request(toolCall(), AUTHENTICATED));

        bearerCheck().audit(base, server.http());

        assertThat(server.received()).filteredOn(sent -> VALID_TOKEN_HEADER.equals(sent.headerValue("Authorization")))
                .filteredOn(sent -> CLIENT_ADDRESS_HEADER_NAMES.stream().noneMatch(sent::hasHeader))
                .hasSize(1);
    }

    @Test
    void baseWhoseReplyIdDoesNotMatchIsResentAsAnAuthenticatedProbe() {
        SimulatedMcpServer server = SimulatedMcpServer.open();
        HttpRequest seed = request(toolCall(), JSON);
        HttpRequestResponse rewrittenByTheProxy = HttpRequestResponse.httpRequestResponse(seed,
                burp.api.montoya.http.message.responses.HttpResponse.httpResponse(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":9999,\"result\":{}}"));

        List<AuditIssue> issues = bearerCheck().audit(rewrittenByTheProxy, server.http());

        assertThat(server.received().get(0).headerValue("Authorization")).isEqualTo(VALID_TOKEN_HEADER);
        assertThat(server.received().get(0).headerValue("X-Mcp-Scanner-Strip-Auth")).isEqualTo("1");
        assertThat(issues).singleElement()
                .satisfies(issue -> assertThat(issue.name()).isEqualTo(FindingKind.ANONYMOUS_EXECUTION.issueName()));
    }

    @Test
    void openServerThatRefusesSessionlessRequestsIsReportedAsOpenNotAsSessionCredential() {
        SimulatedMcpServer server = SimulatedMcpServer.open().requiringSessions().refusingSessionlessRequests();
        String liveSession = server.openAuthenticatedSession();
        HttpRequest seed = request(toolCall(), Map.of("Content-Type", "application/json",
                "Authorization", SimulatedMcpServer.VALID_TOKEN, "Mcp-Session-Id", liveSession));

        List<AuditIssue> issues = audit(check(new NoAuthStrategy()), server, seed.withRemovedHeader("Authorization"));

        assertThat(issues).singleElement()
                .satisfies(issue -> assertThat(issue.name()).isEqualTo(FindingKind.ANONYMOUS_EXECUTION.issueName()));
    }

    @Test
    void aCookieOnTheSeedIsNotTreatedAsConfiguredCredentials() {
        List<AuditIssue> issues = audit(check(new NoAuthStrategy()), SimulatedMcpServer.open(),
                request(toolCall(), Map.of("Content-Type", "application/json", "Cookie", "AWSALB=sticky")));

        assertThat(issues).singleElement()
                .satisfies(issue -> assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE));
    }

    @Nested
    class SweepMemory {

        @Test
        void isClearedWithTheConnection() {
            assertThat(bearerCheck()).isInstanceOf(ConnectionScoped.class);
        }

        @Test
        void aRepeatedMethodOnTheSameEndpointIsNotSweptAgainUntilTheConnectionIsCleared() {
            UnauthenticatedRequestExecutionCheck check = bearerCheck();
            SimulatedMcpServer server = SimulatedMcpServer.enforcing();

            int first = requestsSentAuditing(check, server);
            int repeated = requestsSentAuditing(check, server);
            check.clearConnectionState();
            int afterClearing = requestsSentAuditing(check, server);

            assertThat(repeated).isLessThan(first / 10);
            assertThat(afterClearing).isEqualTo(first);
        }

        @Test
        void aBypassIsStillReportedForEverySeedOfTheMethod() {
            UnauthenticatedRequestExecutionCheck check = bearerCheck();
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/MCP");

            List<AuditIssue> first = audit(check, server, request(toolCall(), AUTHENTICATED));
            List<AuditIssue> repeated = audit(check, server, request(toolCall(), AUTHENTICATED));

            assertThat(first).extracting(AuditIssue::name).containsExactly(FindingKind.AUTHENTICATION_BYPASS.issueName());
            assertThat(repeated).extracting(AuditIssue::name).isEqualTo(first.stream().map(AuditIssue::name).toList());
        }

        private int requestsSentAuditing(UnauthenticatedRequestExecutionCheck check, SimulatedMcpServer server) {
            HttpRequestResponse base = server.exchange(request(toolCall(), AUTHENTICATED));
            int before = server.received().size();
            check.audit(base, server.http());
            return server.received().size() - before;
        }
    }

    @Nested
    class SourceAddressRestriction {

        @Test
        void operationBehindAGateThatTrustsXForwardedForIsMediumFirm() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing()
                    .restrictingSourceAddressesTrusting("X-Forwarded-For");

            assertThat(audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED))).singleElement()
                    .satisfies(issue -> {
                        assertThat(issue.name()).isEqualTo(FindingKind.FORWARDED_CLIENT_ADDRESS_TRUSTED.issueName());
                        assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
                        assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
                        assertThat(issue.detail()).contains("forwarded-for = 127.0.0.1");
                    });
        }

        @Test
        void isProbedBeforeFailingCredentialsCanTripALockout() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing()
                    .restrictingSourceAddressesTrusting("X-Forwarded-For").lockingOutAfterCredentialFailures(2);

            assertThat(audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED))).extracting(AuditIssue::name)
                    .containsExactly(FindingKind.FORWARDED_CLIENT_ADDRESS_TRUSTED.issueName());
        }

        @Test
        void anonymousExecutionOnTheSameRequestIsStillReported() {
            SimulatedMcpServer server = SimulatedMcpServer.open()
                    .restrictingSourceAddressesTrusting("X-Forwarded-For");

            assertThat(audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED))).extracting(AuditIssue::name)
                    .containsExactlyInAnyOrder(FindingKind.FORWARDED_CLIENT_ADDRESS_TRUSTED.issueName(),
                            FindingKind.ANONYMOUS_EXECUTION.issueName());
        }

        @Test
        void bypassOnTheSameRequestIsStillReportedAsHigh() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing()
                    .restrictingSourceAddressesTrusting("X-Forwarded-For").withUnguardedPath("/MCP");

            assertThat(audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED)))
                    .extracting(AuditIssue::name, AuditIssue::severity)
                    .containsExactlyInAnyOrder(
                            org.assertj.core.groups.Tuple.tuple(FindingKind.FORWARDED_CLIENT_ADDRESS_TRUSTED.issueName(),
                                    AuditIssueSeverity.MEDIUM),
                            org.assertj.core.groups.Tuple.tuple(FindingKind.AUTHENTICATION_BYPASS.issueName(),
                                    AuditIssueSeverity.HIGH));
        }

        @Test
        void alternatingTransientFailuresAreNotReportedAsAForwardedClientTrust() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing()
                    .failingEverySecondRequest(503, "{\"error\":\"stream limit reached\"}");

            assertThat(audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED))).extracting(AuditIssue::name)
                    .doesNotContain(FindingKind.FORWARDED_CLIENT_ADDRESS_TRUSTED.issueName());
        }

        @Test
        void isReportedOncePerEndpointMethodUntilTheConnectionIsCleared() {
            UnauthenticatedRequestExecutionCheck check = bearerCheck();
            SimulatedMcpServer server = SimulatedMcpServer.enforcing()
                    .restrictingSourceAddressesTrusting("X-Forwarded-For");

            assertThat(audit(check, server, request(toolCall(), AUTHENTICATED))).hasSize(1);
            assertThat(audit(check, server, request(toolCall(), AUTHENTICATED))).isEmpty();
            check.clearConnectionState();
            assertThat(audit(check, server, request(toolCall(), AUTHENTICATED))).hasSize(1);
        }
    }

    @Nested
    class InvalidCredential {

        private static final String FABRICATED = "Bearer invalid_";

        @Test
        void presenceOnlyOperationIsMediumFirmAndConfirmedWithASecondFabricatedCredential() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().acceptingAnyCredential();
            List<AuditIssue> issues = audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED));

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.name()).isEqualTo(FindingKind.INVALID_CREDENTIAL_ACCEPTED.issueName());
                assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
                assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
                assertThat(issue.requestResponses()).extracting(exchange -> exchange.request().headerValue("Authorization"))
                        .containsExactly(VALID_TOKEN_HEADER, null, "Bearer not_a_real_token_12345");
            });
            assertThat(server.received()).extracting(sent -> sent.headerValue("Authorization"))
                    .anyMatch(value -> value != null && value.startsWith(FABRICATED));
        }

        @Test
        void theAttachedAnonymousRefusalIsTheProbeNotTheRefusedFreshSessionHandshake() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().acceptingAnyCredential();

            assertThat(audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED))).singleElement()
                    .satisfies(issue -> assertThat(issue.requestResponses().get(1).request().bodyToString())
                            .contains("tools/call").doesNotContain("initialize"));
        }

        @Test
        void presenceOnlyCatalogIsInformationFirm() {
            List<AuditIssue> issues = audit(bearerCheck(), SimulatedMcpServer.enforcing().acceptingAnyCredential(),
                    request(toolsList(), AUTHENTICATED));

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.name()).isEqualTo(FindingKind.INVALID_CREDENTIAL_ACCEPTED.issueName());
                assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
                assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            });
        }

        @Test
        void passthroughServerReportsOnlyItsCatalogBecauseItsToolsFailUpstream() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().passingCredentialsToAValidatingUpstream();

            assertThat(audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED))).isEmpty();
            assertThat(audit(bearerCheck(), server, request(toolsList(), AUTHENTICATED))).singleElement()
                    .satisfies(issue -> assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.INFORMATION));
        }

        @Test
        void presenceOnlyProtocolMethodsAndNotificationsAreNotReported() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().acceptingAnyCredential();

            assertThat(audit(bearerCheck(), server, request(ping(), AUTHENTICATED))).isEmpty();
            assertThat(audit(bearerCheck(), server, request(notification(), AUTHENTICATED))).isEmpty();
        }

        @Test
        void aSingleAcceptedPlaceholderThatTheSecondFabricatedCredentialDoesNotReproduceIsNotReported() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().acceptingCredential("Bearer not_a_real_token_12345");

            assertThat(audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED))).isEmpty();
        }

        @Test
        void serverErrorWithoutCredentialsAndAnyCredentialAcceptedIsReported() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().failingWithoutCredentials().acceptingAnyCredential();

            assertThat(audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED))).singleElement()
                    .satisfies(issue -> assertThat(issue.name())
                            .isEqualTo(FindingKind.INVALID_CREDENTIAL_ACCEPTED.issueName()));
        }

        @Test
        void reproducibleServerErrorWithoutCredentialsCountsAsARefusalSoTheSweepRuns() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().failingWithoutCredentials();

            assertThat(audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED))).isEmpty();
            assertThat(server.received()).hasSizeGreaterThan(20);
        }

        @Test
        void serverErrorThatDoesNotReproduceIsInconclusive() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().failingWithoutCredentialsVariably()
                    .acceptingAnyCredential();

            assertThat(audit(bearerCheck(), server, request(toolCall(), AUTHENTICATED))).isEmpty();
            assertThat(server.received()).hasSizeLessThan(6 + CLIENT_ADDRESS_HEADERS);
        }

        @Test
        void openStatefulServerThatFailsWithoutASessionIsReportedAsOpenNotAsSessionCredential() {
            SimulatedMcpServer server = SimulatedMcpServer.open().requiringSessions().failingWithoutSessions();
            String liveSession = server.openAuthenticatedSession();
            HttpRequest seed = request(toolCall(), Map.of("Content-Type", "application/json",
                    "Authorization", VALID_TOKEN_HEADER, "Mcp-Session-Id", liveSession));

            assertThat(audit(bearerCheck(), server, seed)).singleElement()
                    .satisfies(issue -> assertThat(issue.name()).isEqualTo(FindingKind.ANONYMOUS_EXECUTION.issueName()));
        }
    }

    @Nested
    class ToolErrorRefusal {

        @Test
        void sessionCredentialBehindAToolErrorRefusalIsReached() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().requiringSessions().authenticatingBySession()
                    .refusingWithToolError("This tool is not available. This tool requires a valid Terraform "
                            + "Cloud/Enterprise token and configuration.");
            String liveSession = server.openAuthenticatedSession();
            HttpRequest seed = request(toolCall(), Map.of("Content-Type", "application/json",
                    "Authorization", VALID_TOKEN_HEADER, "Mcp-Session-Id", liveSession));

            assertThat(audit(bearerCheck(), server, seed)).singleElement()
                    .satisfies(issue -> assertThat(issue.name()).isEqualTo(FindingKind.SESSION_CREDENTIAL.issueName()));
        }

        @Test
        void ordinaryToolErrorForAnonymousCallersStopsTheAudit() {
            SimulatedMcpServer server = SimulatedMcpServer.enforcing().requiringSessions().authenticatingBySession()
                    .refusingWithToolError("EACCES: permission denied, open '/srv/data'");
            String liveSession = server.openAuthenticatedSession();
            HttpRequest seed = request(toolCall(), Map.of("Content-Type", "application/json",
                    "Authorization", VALID_TOKEN_HEADER, "Mcp-Session-Id", liveSession));

            assertThat(audit(bearerCheck(), server, seed)).isEmpty();
            assertThat(server.received()).hasSizeLessThan(8);
        }
    }
}
