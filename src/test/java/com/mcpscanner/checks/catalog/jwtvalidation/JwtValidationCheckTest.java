package com.mcpscanner.checks.catalog.jwtvalidation;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.api.AccessLedger;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.PrincipalListings;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.checks.api.SkipSubject;
import com.mcpscanner.checks.issue.Cwe;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import static com.mcpscanner.checks.catalog.jwtvalidation.FakeJwtServer.TOOLS_LIST;
import static com.mcpscanner.checks.catalog.jwtvalidation.FakeJwtServer.TOOL_CALL;
import static com.mcpscanner.checks.catalog.jwtvalidation.FakeJwtServer.algorithm;
import static com.mcpscanner.checks.catalog.jwtvalidation.FakeJwtServer.hmacSignedWith;
import static com.mcpscanner.checks.catalog.jwtvalidation.FakeJwtServer.seed;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JwtValidationCheckTest {

    private static final String RS256 = TestTokens.RS256_TOKEN;
    private static final String HS256 = TestTokens.HS256_TOKEN;

    private Supplier<AuthStrategy> authStrategy = NoAuthStrategy::new;
    private final McpEventLog eventLog = mock(McpEventLog.class);

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    private JwtValidationCheck check() {
        return (JwtValidationCheck) new JwtValidationCheckFactory().create(new CheckServices(eventLog,
                () -> authStrategy.get(), Optional::empty, Optional::empty,
                PrincipalRoster::empty, AccessLedger.noop(), PrincipalListings.unknown()));
    }

    private List<AuditIssue> audit(FakeJwtServer server, String body, String token) {
        return check().audit(seed(body, "Bearer " + token), server.http());
    }

    @Nested
    class Descriptor {

        @Test
        void isAHighSeverityHostCheckRegisteredInTheCatalog() {
            CheckCatalog catalog = CheckCatalog.discover(CheckServices.standalone());

            assertThat(catalog.find("jwt-validation")).get().isInstanceOf(JwtValidationCheck.class);
            assertThat(JwtValidationDescriptor.DESCRIPTOR.kind()).isEqualTo(CheckKind.HOST);
            assertThat(JwtValidationDescriptor.DESCRIPTOR.headlineSeverity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(JwtValidationDescriptor.DESCRIPTOR.headlineConfidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(JwtValidationDescriptor.DESCRIPTOR.cwes()).extracting(Cwe::id).containsExactly(347, 287);
            assertThat(JwtValidationDescriptor.DESCRIPTOR.references()).isNotEmpty();
        }
    }

    @Nested
    class AppliesTo {

        @Test
        void appliesToAJsonRpcCallCarryingAJwtBearer() {
            assertThat(check().appliesTo(seed(TOOL_CALL, "Bearer " + RS256))).isTrue();
            assertThat(check().appliesTo(seed(TOOL_CALL.replace("tools/call", "resources/read"), "bearer " + RS256)))
                    .isTrue();
            assertThat(check().appliesTo(seed(TOOL_CALL.replace("tools/call", "prompts/get"), "Bearer " + RS256)))
                    .isTrue();
        }

        @Test
        void usesTheSessionBearerWhenTheRequestCarriesNone() {
            authStrategy = () -> new BearerTokenAuthStrategy(RS256);

            assertThat(check().appliesTo(seed(TOOL_CALL, null))).isTrue();
        }

        @Test
        void doesNotApplyWithoutAJwtBearer() {
            assertThat(check().appliesTo(seed(TOOL_CALL, null))).isFalse();
            assertThat(check().appliesTo(seed(TOOL_CALL, "Bearer opaque-token"))).isFalse();
            assertThat(check().appliesTo(seed(TOOL_CALL, "Basic " + RS256))).isFalse();
        }

        @Test
        void doesNotApplyToInitializeNotificationsOrNonJsonRpcBodies() {
            String bearer = "Bearer " + RS256;
            assertThat(check().appliesTo(seed("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}", bearer)))
                    .isFalse();
            assertThat(check().appliesTo(seed("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}",
                    bearer))).isFalse();
            assertThat(check().appliesTo(seed(TOOL_CALL.replace("\"id\":7", "\"id\":null"), bearer))).isFalse();
            assertThat(check().appliesTo(seed(TOOLS_LIST, bearer))).isFalse();
            assertThat(check().appliesTo(seed("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}", bearer))).isFalse();
            assertThat(check().appliesTo(seed("[" + TOOL_CALL + "]", bearer))).isFalse();
            assertThat(check().appliesTo(seed("not json", bearer))).isFalse();
            assertThat(check().appliesTo(seed("{\"id\":1,\"method\":\"tools/list\"}", bearer))).isFalse();
        }

        @Test
        void doesNotApplyToNonPostRequests() {
            HttpRequestResponse seed = seed(TOOL_CALL, "Bearer " + RS256);
            HttpRequestResponse get = HttpRequestResponse.httpRequestResponse(
                    seed.request().withMethod("GET"), seed.response());

            assertThat(check().appliesTo(get)).isFalse();
        }
    }

    @Nested
    class SecureServers {

        @Test
        void aServerThatVerifiesSignaturesYieldsNoIssue() {
            FakeJwtServer server = new FakeJwtServer(HS256);

            assertThat(audit(server, TOOL_CALL, HS256)).isEmpty();
        }

        @Test
        void sendsOnlyTheBaselineControlsAndOneProbePerArmWhenNothingIsAccepted() {
            FakeJwtServer server = new FakeJwtServer(HS256);

            audit(server, TOOL_CALL, HS256);

            assertThat(server.received()).hasSize(6);
        }

        @Test
        void everyProbeKeepsTheSeedBodyAndCarriesTheStripSentinel() {
            FakeJwtServer server = new FakeJwtServer(HS256);

            audit(server, TOOL_CALL, HS256);

            assertThat(server.received()).allSatisfy(request -> {
                assertThat(request.bodyToString()).isEqualTo(TOOL_CALL);
                assertThat(request.headerValue(ScannerSentinels.STRIP_AUTH_HEADER)).isEqualTo("1");
            });
            assertThat(server.received().get(0).headerValue("Authorization")).isEqualTo("Bearer " + HS256);
            assertThat(server.received().get(1).headerValue("Authorization")).isNull();
            assertThat(server.received().get(2).headerValue("Authorization"))
                    .isEqualTo("Bearer " + ForgedTokenAudit.MALFORMED_TOKEN);
        }

        @Test
        void forgedTokensCarryTheCapturedClaims() {
            FakeJwtServer server = new FakeJwtServer(HS256);

            audit(server, TOOL_CALL, HS256);

            assertThat(server.bearersReceived().subList(2, 5)).allSatisfy(token ->
                    assertThat(TestTokens.claimsOf(token)).isEqualTo(TestTokens.claimsOf(HS256)));
        }
    }

    @Nested
    class ControlsGateEveryFinding {

        @Test
        void anAnonymouslyOpenServerYieldsNoJwtIssue() {
            FakeJwtServer server = new FakeJwtServer(RS256).allowingAnonymous().accepting(algorithm("none"));

            assertThat(audit(server, TOOL_CALL, RS256)).isEmpty();
            assertThat(server.received()).hasSize(3);
        }

        @Test
        void aRefusalThatLiftsAfterTheBaselineIsNotReportedAsAForgedTokenFlaw() {
            FakeJwtServer server = new FakeJwtServer(RS256).openToEveryoneAfter(3);

            assertThat(audit(server, TOOL_CALL, RS256)).isEmpty();
        }

        @Test
        void controlsAreSentAgainAfterEveryAcceptedForgery() {
            FakeJwtServer server = new FakeJwtServer(RS256).accepting(algorithm("none"));

            audit(server, TOOL_CALL, RS256);

            assertThat(server.received().stream().filter(request -> "POST".equals(request.method()))
                    .filter(request -> request.headerValue("Authorization") == null)).hasSize(2);
        }

        @Test
        void aServerThatAcceptsAnyBearerYieldsNoJwtIssue() {
            FakeJwtServer server = new FakeJwtServer(RS256).allowingAnyBearer();

            assertThat(audit(server, TOOL_CALL, RS256)).isEmpty();
        }

        @Test
        void aFailingBaselineYieldsNoIssue() {
            FakeJwtServer server = new FakeJwtServer("other.token.value").accepting(algorithm("none"));

            assertThat(audit(server, TOOL_CALL, RS256)).isEmpty();
            assertThat(server.received()).hasSize(3);
        }

        @Test
        void aForgeryAnsweredWithADifferentOperationResultIsNotAccepted() {
            FakeJwtServer server = new FakeJwtServer(RS256).accepting(algorithm("none"))
                    .answeringForgeries(FakeJwtServer.SECRET.replace("s3cr3t", "Please sign in first"));

            assertThat(audit(server, TOOL_CALL, RS256)).isEmpty();
        }
    }

    @Nested
    class SkipLogging {

        private static final String PREFIX = "Scan check: jwt-validation — ";

        private String subject;

        @BeforeEach
        void captureSubject() {
            subject = SkipSubject.of(seed(TOOL_CALL, "Bearer " + RS256));
        }

        @Test
        void anAnonymouslyOpenServerIsSkippedBecauseTheControlsAreAnswered() {
            audit(new FakeJwtServer(RS256).allowingAnonymous(), TOOL_CALL, RS256);

            verify(eventLog).info(PREFIX + "skipped " + subject
                    + " (prerequisite missing: the request is answered without a valid credential)");
        }

        @Test
        void aFailingBaselineIsSkippedBecauseTheCapturedJwtDoesNotWork() {
            audit(new FakeJwtServer("other.token.value"), TOOL_CALL, RS256);

            verify(eventLog).info(PREFIX + "skipped " + subject
                    + " (prerequisite missing: the replay with the captured JWT did not succeed)");
        }

        @Test
        void keepsAForgeryProvenBeforeAnHttp429() {
            FakeJwtServer unlimited = new FakeJwtServer(RS256).accepting(algorithm("none"));
            audit(unlimited, TOOL_CALL, RS256);
            int proven = provenAfter(unlimited.received());
            FakeJwtServer server = new FakeJwtServer(RS256).accepting(algorithm("none")).throttlingAfter(proven);

            assertThat(audit(server, TOOL_CALL, RS256)).isNotEmpty();

            verify(eventLog).info(PREFIX + "stopped " + subject + " (rate limited: the server answered HTTP 429)");
        }

        @Test
        void reportsAForgeryWhoseAcceptingReplySaysTheRateLimitQuotaIsSpent() {
            FakeJwtServer unlimited = new FakeJwtServer(RS256).accepting(algorithm("none"));
            audit(unlimited, TOOL_CALL, RS256);
            FakeJwtServer server = new FakeJwtServer(RS256).accepting(algorithm("none"))
                    .spendingQuotaAfter(unsignedForgeryIndex(unlimited.received()));

            assertThat(audit(server, TOOL_CALL, RS256)).singleElement()
                    .satisfies(issue -> assertThat(issue.detail()).contains("alg: none"));
        }

        @Test
        void aSpentRateLimitQuotaOnARefusedForgeryStopsFurtherForgeries() {
            FakeJwtServer server = new FakeJwtServer(RS256).spendingQuotaAfter(3);

            assertThat(audit(server, TOOL_CALL, RS256)).isEmpty();

            assertThat(server.received()).hasSize(4);
        }

        private int provenAfter(List<HttpRequest> received) {
            return unsignedForgeryIndex(received) + 3;
        }

        private int unsignedForgeryIndex(List<HttpRequest> received) {
            for (int index = 0; index < received.size(); index++) {
                String authorization = received.get(index).headerValue("Authorization");
                if (authorization != null && algorithm("none").test(authorization.substring("Bearer ".length()))) {
                    return index;
                }
            }
            throw new AssertionError("no unsigned forgery was sent");
        }

        @Test
        void http429StopsTheForgeriesAndSaysSo() {
            FakeJwtServer server = new FakeJwtServer(RS256).throttlingAfter(3);

            assertThat(audit(server, TOOL_CALL, RS256)).isEmpty();

            assertThat(server.received()).hasSize(4);
            verify(eventLog).info(PREFIX + "stopped " + subject + " (rate limited: the server answered HTTP 429)");
        }

        @Test
        void controlsThatStopBeingRefusedAreLoggedOnceAsAMissingPrerequisite() {
            audit(new FakeJwtServer(RS256).openToEveryoneAfter(3), TOOL_CALL, RS256);

            verify(eventLog).info(PREFIX + "skipped the accepted forgeries for " + subject
                    + " (prerequisite missing: the refusal controls were no longer refused after a forgery was "
                    + "accepted)");
        }

        @Test
        void aSecureServerLogsNoSkip() {
            audit(new FakeJwtServer(RS256), TOOL_CALL, RS256);

            verify(eventLog, never()).info(contains("skipped"));
            verify(eventLog, never()).info(contains("stopped"));
        }
    }

    @Nested
    class AcceptedForgeries {

        @Test
        void algNoneAcceptanceIsAHighFirmIssueOnAToolCall() {
            FakeJwtServer server = new FakeJwtServer(RS256).accepting(algorithm("none"));

            List<AuditIssue> issues = audit(server, TOOL_CALL, RS256);

            assertThat(issues).singleElement().satisfies(issue -> {
                assertThat(issue.name()).isEqualTo(JwtValidationDescriptor.DESCRIPTOR.issueName());
                assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
                assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
                assertThat(issue.detail()).contains("alg: none").contains("appear to be checked");
                assertThat(issue.requestResponses()).hasSize(3);
            });
        }

        @Test
        void randomKeyRs256AcceptanceIsReported() {
            FakeJwtServer server = new FakeJwtServer(RS256).accepting(algorithm("RS256"));

            assertThat(audit(server, TOOL_CALL, RS256)).singleElement()
                    .satisfies(issue -> assertThat(issue.detail()).contains("freshly generated RSA key"));
        }

        @Test
        void claimsAreReportedUnvalidatedWhenTheAcceptedForgeryIgnoresThem() {
            FakeJwtServer server = new FakeJwtServer(RS256).accepting(algorithm("none")).ignoringClaims();

            AuditIssue issue = audit(server, TOOL_CALL, RS256).get(0);

            assertThat(issue.detail()).contains("does not validate").contains("issuer (iss)", "audience (aud)",
                    "expiry (exp)").doesNotContain("appear to be checked");
            assertThat(issue.requestResponses()).hasSize(6);
        }

        @Test
        void claimsAreProbedOnlyOnceWithTheFirstAcceptedForgery() {
            FakeJwtServer server = new FakeJwtServer(RS256).accepting(algorithm("none")).accepting(algorithm("RS256"));

            audit(server, TOOL_CALL, RS256);

            assertThat(server.received().stream().filter(request -> "POST".equals(request.method()))).hasSize(
                    3 + (1 + 2 + 3) + (1 + 2) + 1);
        }

        @Test
        void emptySecretWithUnknownKeyIdIsReportedWhenTheRandomSecretControlIsRefused() {
            FakeJwtServer server = new FakeJwtServer(HS256).accepting(hmacSignedWith(new byte[0]));

            AuditIssue issue = audit(server, TOOL_CALL, HS256).get(0);

            assertThat(issue.detail()).contains("unknown key id (kid) and an empty HMAC secret");
            assertThat(issue.requestResponses()).anySatisfy(exchange -> assertThat(exchange.response().statusCode())
                    .isEqualTo((short) 401));
        }

        @Test
        void anyHs256SignatureAcceptedIsReportedAsUnverifiedHmacOnce() {
            FakeJwtServer server = new FakeJwtServer(HS256).accepting(algorithm("HS256"));

            AuditIssue issue = audit(server, TOOL_CALL, HS256).get(0);

            assertThat(issue.detail()).contains("random HMAC secret").doesNotContain("empty HMAC secret");
        }
    }

    @Nested
    class Evidence {

        @Test
        void anUncontrolledForgeryAttachesTheBaselineTheMalformedRefusalItsTokenAndEachAcceptedClaim() {
            FakeJwtServer server = new FakeJwtServer(RS256).accepting(algorithm("none")).ignoringClaims();

            List<String> tokens = attachedTokens(audit(server, TOOL_CALL, RS256).get(0));

            assertThat(tokens).hasSize(6);
            assertThat(tokens.get(0)).isEqualTo(RS256);
            assertThat(tokens.get(1)).isEqualTo(ForgedTokenAudit.MALFORMED_TOKEN);
            assertThat(tokens.get(2)).matches(algorithm("none")).satisfies(token ->
                    assertThat(TestTokens.claimsOf(token)).isEqualTo(TestTokens.claimsOf(RS256)));
            assertThat(tokens.subList(3, 6)).allSatisfy(token -> {
                assertThat(token).matches(algorithm("none"));
                assertThat(TestTokens.claimsOf(token)).isNotEqualTo(TestTokens.claimsOf(RS256));
            });
        }

        @Test
        void aControlledForgeryAlsoAttachesItsRefusedWrongKeyControl() {
            byte[] empty = new byte[0];
            FakeJwtServer server = new FakeJwtServer(HS256).accepting(hmacSignedWith(empty)).ignoringClaims();

            AuditIssue issue = audit(server, TOOL_CALL, HS256).get(0);
            List<String> tokens = attachedTokens(issue);

            assertThat(tokens).hasSize(7);
            assertThat(tokens.get(0)).isEqualTo(HS256);
            assertThat(tokens.get(1)).isEqualTo(ForgedTokenAudit.MALFORMED_TOKEN);
            assertThat(tokens.get(2)).matches(hmacSignedWith(empty));
            assertThat(tokens.get(3)).matches(algorithm("HS256")).isNotEqualTo(tokens.get(2));
            assertThat(hmacSignedWith(empty).test(tokens.get(3))).isFalse();
            assertThat(issue.requestResponses().get(3).response().statusCode()).isEqualTo((short) 401);
            assertThat(tokens.subList(4, 7)).allSatisfy(token -> assertThat(token).matches(hmacSignedWith(empty)));
        }

        @Test
        void onlyTheFirstAcceptedForgeryIsAttached() {
            FakeJwtServer server = new FakeJwtServer(RS256).accepting(algorithm("none")).accepting(algorithm("RS256"));

            AuditIssue issue = audit(server, TOOL_CALL, RS256).get(0);
            List<String> tokens = attachedTokens(issue);

            assertThat(issue.detail()).contains("alg: none").contains("freshly generated RSA key")
                    .contains("before and again after each forged token")
                    .contains("which was not accepted")
                    .contains("The no-credential refusal, the other forged tokens and the repeated refusal controls "
                            + "are not attached.");
            assertThat(tokens).hasSize(3);
            assertThat(tokens.get(0)).isEqualTo(RS256);
            assertThat(tokens.get(1)).isEqualTo(ForgedTokenAudit.MALFORMED_TOKEN);
            assertThat(tokens.get(2)).isNotEqualTo(RS256).matches(algorithm("RS256"));
        }

        private List<String> attachedTokens(AuditIssue issue) {
            return issue.requestResponses().stream()
                    .map(exchange -> exchange.request().headerValue("Authorization").substring("Bearer ".length()))
                    .toList();
        }
    }

    @Nested
    class PublicKeyConfusion {

        private RSAPublicKey key;
        private String token;

        @BeforeEach
        void publishKey() throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            key = (RSAPublicKey) generator.generateKeyPair().getPublic();
            token = TestTokens.token("{\"alg\":\"RS256\",\"kid\":\"k1\"}",
                    "{\"iss\":\"https://mcp.example\",\"aud\":\"https://mcp.example/mcp\",\"exp\":4102444800}");
        }

        private FakeJwtServer serverPublishingTheKey() {
            Base64.Encoder url = Base64.getUrlEncoder().withoutPadding();
            return new FakeJwtServer(token)
                    .publishing("https://mcp.example:443/.well-known/oauth-protected-resource/mcp",
                            "{\"authorization_servers\":[\"https://mcp.example\"]}")
                    .publishing("https://mcp.example/.well-known/oauth-authorization-server",
                            "{\"jwks_uri\":\"https://mcp.example/jwks.json\"}")
                    .publishing("https://mcp.example/jwks.json", "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"k1\","
                            + "\"n\":\"" + url.encodeToString(unsigned(key.getModulus())) + "\",\"e\":\""
                            + url.encodeToString(unsigned(key.getPublicExponent())) + "\"}]}");
        }

        @Test
        void hs256KeyedWithThePublishedPemIsReported() {
            byte[] pem = pem(key.getEncoded()).getBytes(StandardCharsets.US_ASCII);
            FakeJwtServer server = serverPublishingTheKey().accepting(hmacSignedWith(pem));

            AuditIssue issue = check().audit(seed(TOOL_CALL, "Bearer " + token), server.http()).get(0);

            assertThat(issue.detail()).contains("HMAC secret is the public key k1").contains("SPKI PEM");
        }

        @Test
        void aServerVerifyingRs256IsSilentAfterTryingEveryPublishedEncoding() {
            FakeJwtServer server = serverPublishingTheKey();

            assertThat(check().audit(seed(TOOL_CALL, "Bearer " + token), server.http())).isEmpty();
            assertThat(server.received().stream().filter(request -> "GET".equals(request.method()))).isNotEmpty();
            assertThat(server.received().stream().filter(request -> "POST".equals(request.method()))).hasSize(
                    3 + 2 + 4 + 1);
        }

        private static String pem(byte[] der) {
            return "-----BEGIN PUBLIC KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
                    + "\n-----END PUBLIC KEY-----\n";
        }

        private static byte[] unsigned(BigInteger value) {
            byte[] bytes = value.toByteArray();
            return bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
        }
    }

    @Test
    void auditReturnsNothingWhenTheSeedLostItsBearer() {
        HttpRequest seedRequest = seed(TOOL_CALL, null).request();
        HttpRequestResponse seed = mock(HttpRequestResponse.class);
        when(seed.request()).thenReturn(seedRequest);

        assertThat(check().audit(seed, new FakeJwtServer(RS256).http())).isEmpty();
    }
}
