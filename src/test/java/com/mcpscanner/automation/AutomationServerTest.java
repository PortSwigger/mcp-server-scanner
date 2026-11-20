package com.mcpscanner.automation;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AutomationServerTest {

    private final HeadlessScanAll scanAll = mock(HeadlessScanAll.class);
    private final LaunchedAudit audit = mock(LaunchedAudit.class);
    private final HeadlessCheckAccess checkAccess = mock(HeadlessCheckAccess.class);
    private final SendCanary sendCanary = mock(SendCanary.class);
    private final SignedInSessionSeed signedInSession = mock(SignedInSessionSeed.class);
    private final AuthProbe authProbe = mock(AuthProbe.class);
    private final AuditPathCanary auditPathCanary = mock(AuditPathCanary.class);
    private final AutomationServer server = new AutomationServer(0, scanAll, audit, checkAccess, sendCanary,
            signedInSession, authProbe, auditPathCanary).start();
    private final HttpClient client = HttpClient.newHttpClient();

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void scanAllReturnsHowManyRequestsWereAudited() throws Exception {
        when(scanAll.launch(any())).thenReturn(new LaunchedScan(19));

        HttpResponse<String> response = post("{\"endpoint\":\"http://127.0.0.1:1/mcp\",\"checks\":[\"file-traversal\"]}");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("{\"requests\":19}");
    }

    @Test
    void scanAllTakesACatalogLimitAndSaysWhenItTrimmedTheCatalog() throws Exception {
        when(scanAll.launch(argThat(command -> Integer.valueOf(50).equals(command.maxCatalogItems()))))
                .thenReturn(new LaunchedScan(51, "catalog limited to 50 items per kind (tools 124 -> 50)"));

        HttpResponse<String> response = post("{\"endpoint\":\"http://127.0.0.1:1/mcp\",\"maxCatalogItems\":50}");

        assertThat(response.body())
                .isEqualTo("{\"requests\":51,\"catalogLimit\":\"catalog limited to 50 items per kind (tools 124 -> 50)\"}");
    }

    @Test
    void aFailedScanAllAnswers500WithTheReason() throws Exception {
        when(scanAll.launch(any())).thenThrow(new IllegalStateException("Failed to establish scanner session"));

        HttpResponse<String> response = post("{\"endpoint\":\"http://127.0.0.1:1/mcp\"}");

        assertThat(response.statusCode()).isEqualTo(500);
        assertThat(response.body()).contains("IllegalStateException: Failed to establish scanner session");
    }

    @Test
    void anUnreadableCommandAnswers500() throws Exception {
        assertThat(post("not json").statusCode()).isEqualTo(500);
    }

    @Test
    void scanAllAcceptsOnlyPost() throws Exception {
        assertThat(get("/scan-all").statusCode()).isEqualTo(405);
    }

    @Test
    void auditAnswers404UntilAnAuditIsLaunchedThenItsSnapshot() throws Exception {
        when(audit.snapshot()).thenReturn(Optional.empty())
                .thenReturn(Optional.of(new AuditSnapshot("finished", 5, 0, 2, 3, 3, List.of(), 0, Map.of())));

        assertThat(get("/audit").statusCode()).isEqualTo(404);
        HttpResponse<String> launched = get("/audit");
        assertThat(launched.statusCode()).isEqualTo(200);
        assertThat(launched.body()).contains("\"status\":\"finished\"", "\"requestCount\":5");
    }

    @Test
    void refusesAScanAllThatIsNotJsonSoAPageCannotSendItWithoutAPreflight() throws Exception {
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(uri("/scan-all"))
                .header("Content-Type", "text/plain")
                .POST(HttpRequest.BodyPublishers.ofString("{\"endpoint\":\"http://127.0.0.1:1/mcp\"}")).build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(415);
        org.mockito.Mockito.verifyNoInteractions(scanAll);
    }

    @Test
    void refusesAnyRequestABrowserSentWithAnOrigin() throws Exception {
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(uri("/audit"))
                .header("Origin", "http://attacker.example").GET().build(), HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(403);
        org.mockito.Mockito.verifyNoInteractions(audit);
    }

    @Test
    void checkAccessAnswersWithTheLaunchedStatus() throws Exception {
        when(checkAccess.launch(any())).thenReturn(status(CheckAccessPhase.DISCOVERING, List.of()));

        HttpResponse<String> response = post(AutomationServer.CHECK_ACCESS_PATH, """
                {"endpoint":"http://127.0.0.1:1/mcp","transport":"STREAMABLE_HTTP","auth":{"bearerToken":"t"},
                 "useBurpNetworking":false,"identities":{"connectAs":{"name":"alice"}}}""");

        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(response.body()).contains("\"status\":\"discovering\"");
        org.mockito.Mockito.verify(checkAccess).launch(new CheckAccessCommand("http://127.0.0.1:1/mcp",
                com.mcpscanner.client.TransportType.STREAMABLE_HTTP, new CommandAuth("t", Map.of()), false,
                new CommandIdentities(new CommandUser("alice", null, null, null, null), null, null, null, null)));
    }

    @Test
    void aCheckAccessThatCannotConnectAnswers500WithTheReason() throws Exception {
        when(checkAccess.launch(any())).thenThrow(new IllegalStateException("Check access is already running"));

        HttpResponse<String> response = post(AutomationServer.CHECK_ACCESS_PATH, "{\"endpoint\":\"http://127.0.0.1:1/mcp\"}");

        assertThat(response.statusCode()).isEqualTo(500);
        assertThat(response.body()).contains("Check access is already running");
    }

    @Test
    void checkAccessStatusAnswers404UntilLaunchedThenTheStatusWithFiledIssues() throws Exception {
        ReportedIssue filed = new ReportedIssue("MCP operation result available to another principal", "HIGH",
                "FIRM", "http://127.0.0.1:1", "detail", true, List.of());
        when(checkAccess.status()).thenReturn(Optional.empty())
                .thenReturn(Optional.of(status(CheckAccessPhase.FINISHED, List.of(filed))));

        assertThat(get(AutomationServer.CHECK_ACCESS_PATH).statusCode()).isEqualTo(404);
        HttpResponse<String> finished = get(AutomationServer.CHECK_ACCESS_PATH);

        assertThat(finished.statusCode()).isEqualTo(200);
        assertThat(finished.body()).contains("\"status\":\"finished\"", "\"checked\":2", "\"total\":2",
                "\"requestsReached\":5", "MCP operation result available to another principal");
    }

    @Test
    void checkAccessRefusesAPostThatIsNotJson() throws Exception {
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(uri(AutomationServer.CHECK_ACCESS_PATH))
                .header("Content-Type", "text/plain")
                .POST(HttpRequest.BodyPublishers.ofString("{\"endpoint\":\"http://127.0.0.1:1/mcp\"}")).build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(415);
        org.mockito.Mockito.verifyNoInteractions(checkAccess);
    }

    @Test
    void checkAccessAcceptsOnlyPostAndGet() throws Exception {
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(uri(AutomationServer.CHECK_ACCESS_PATH))
                .DELETE().build(), HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(405);
    }

    @Test
    void sendCanaryReturnsThePerSendLatencies() throws Exception {
        when(sendCanary.run(new SendCanaryCommand("http://127.0.0.1:9/canary", 2, 1)))
                .thenReturn(new SendCanaryReport(List.of(1_500L, 2_500L), 4_000L, 0));

        HttpResponse<String> response = post("/send-canary",
                "{\"url\":\"http://127.0.0.1:9/canary\",\"count\":2,\"concurrency\":1}");

        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(response.body())
                .isEqualTo("{\"latenciesMicros\":[1500,2500],\"wallMicros\":4000,\"unanswered\":0}");
    }

    @Test
    void sendCanaryAnswers500ForACommandOutsideItsBounds() throws Exception {
        HttpResponse<String> response = post("/send-canary",
                "{\"url\":\"http://127.0.0.1:9/canary\",\"count\":0,\"concurrency\":1}");

        assertThat(response.statusCode()).isEqualTo(500);
        org.mockito.Mockito.verifyNoInteractions(sendCanary);
    }

    @Test
    void sendCanaryAcceptsOnlyJsonPosts() throws Exception {
        assertThat(get("/send-canary").statusCode()).isEqualTo(405);
        HttpResponse<String> plainText = client.send(HttpRequest.newBuilder(uri("/send-canary"))
                .header("Content-Type", "text/plain")
                .POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(plainText.statusCode()).isEqualTo(415);
        org.mockito.Mockito.verifyNoInteractions(sendCanary);
    }

    @Test
    void signedInSessionSeedsTheCookieJarAndOptsIn() throws Exception {
        when(signedInSession.apply(new SignedInSessionCommand(
                List.of(new CommandCookie("auth.example.test", "/", "sid", "abc")), true)))
                .thenReturn(new SignedInSessionSeeded(1, true));

        HttpResponse<String> response = post("/signed-in-session",
                "{\"cookies\":[{\"domain\":\"auth.example.test\",\"path\":\"/\",\"name\":\"sid\","
                        + "\"value\":\"abc\"}],\"optIn\":true}");

        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(response.body()).isEqualTo("{\"cookies\":1,\"optedIn\":true}");
    }

    @Test
    void signedInSessionAcceptsOnlyJsonPosts() throws Exception {
        assertThat(get("/signed-in-session").statusCode()).isEqualTo(405);
        org.mockito.Mockito.verifyNoInteractions(signedInSession);
    }

    @Test
    void authProbeReturnsTheTimedClassification() throws Exception {
        when(authProbe.run(new AuthProbeCommand("http://127.0.0.1:9/mcp", true)))
                .thenReturn(new AuthProbeReport("NotRequired", "NotRequired[]", 12L));

        HttpResponse<String> response = post("/auth-probe",
                "{\"url\":\"http://127.0.0.1:9/mcp\",\"useBurpNetworking\":true}");

        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        assertThat(response.body())
                .isEqualTo("{\"requirement\":\"NotRequired\",\"detail\":\"NotRequired[]\",\"elapsedMillis\":12}");
    }

    @Test
    void authProbeAcceptsOnlyJsonPosts() throws Exception {
        assertThat(get("/auth-probe").statusCode()).isEqualTo(405);
        assertThat(post("/auth-probe", "{\"url\":\"file:///etc/passwd\",\"useBurpNetworking\":true}")
                .statusCode()).isEqualTo(500);
        org.mockito.Mockito.verifyNoInteractions(authProbe);
    }

    @Test
    void listensOnLoopbackOnly() {
        assertThat(server.port()).isPositive();
        assertThat(server.address().getAddress().isLoopbackAddress()).isTrue();
    }

    private static CheckAccessStatus status(CheckAccessPhase phase, List<ReportedIssue> issues) {
        return new CheckAccessStatus(phase, 2, 2, 6, 5, issues, null);
    }

    private HttpResponse<String> post(String body) throws Exception {
        return post("/scan-all", body);
    }

    private HttpResponse<String> post(String path, String body) throws Exception {
        return client.send(HttpRequest.newBuilder(uri(path)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path) throws Exception {
        return client.send(HttpRequest.newBuilder(uri(path)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + server.port() + path);
    }
}
