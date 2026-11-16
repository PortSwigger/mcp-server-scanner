package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.sitemap.SiteMap;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.automation.AutomationServer;
import com.mcpscanner.automation.TestAutomationSwitch;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.proxy.McpHttpHandler;
import com.mcpscanner.testutil.ClientCertificateBurpHttp;
import com.mcpscanner.testutil.HandlerRoutedBurpHttp;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.StreamingCampaignServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CheckAccessAutomationWiringTest {

    private static final Duration RUN_BOUND = Duration.ofSeconds(60);
    private static final Pattern LISTENING = Pattern.compile("Test automation listening on 127\\.0\\.0\\.1:(\\d+)");
    private static final String CROSS_USER_ISSUE = "MCP operation result available to another principal";

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private final Extension extension = mock(Extension.class);
    private final Http http = mock(Http.class);
    private final List<AuditIssue> siteMap = new CopyOnWriteArrayList<>();
    private final HttpClient client = HttpClient.newHttpClient();
    private StreamingCampaignServer server;

    @BeforeEach
    void setUp() throws Exception {
        MontoyaTestFactory.install();
        renderRequestsAsImmutable();
        when(api.extension()).thenReturn(extension);
        PersistedObject savedSettings = InMemoryPersistedObject.create();
        when(api.persistence().extensionData()).thenReturn(savedSettings);
        when(api.http()).thenReturn(http);
        SiteMap burpSiteMap = mock(SiteMap.class);
        when(api.siteMap()).thenReturn(burpSiteMap);
        when(burpSiteMap.issues()).thenReturn(List.of());
        doAnswer(invocation -> siteMap.add(invocation.getArgument(0))).when(burpSiteMap).add(any(AuditIssue.class));
        routeThroughTheExtensionsHandler();
    }

    @AfterEach
    void unload() {
        ArgumentCaptor<ExtensionUnloadingHandler> unloading = ArgumentCaptor.forClass(ExtensionUnloadingHandler.class);
        verify(extension, atLeastOnce()).registerUnloadingHandler(unloading.capture());
        unloading.getAllValues().forEach(ExtensionUnloadingHandler::extensionUnloaded);
        server.close();
    }

    @Test
    void checkAccessConnectsMinesAndReportsTheCrossUserCampaignItFiledInTheSiteMap() throws Exception {
        server = StreamingCampaignServer.vulnerable();
        int port = initializeWithAutomation();

        HttpResponse<String> launched = post(port, aliceComparingBob());
        JsonNode finished = awaitEnded(port);

        assertThat(launched.statusCode()).as(launched.body()).isEqualTo(200);
        assertThat(finished.path("status").asText()).as(finished.toString()).isEqualTo("finished");
        assertThat(finished.path("total").asInt()).isEqualTo(1);
        assertThat(finished.path("requestsReached").asInt()).isPositive();
        assertThat(finished.path("issues")).extracting(issue -> issue.path("name").asText())
                .isNotEmpty().containsOnly(CROSS_USER_ISSUE);
        assertThat(siteMap).extracting(AuditIssue::name).hasSize(finished.path("issues").size())
                .containsOnly(CROSS_USER_ISSUE);
    }

    @Test
    void checkAccessOfAnOwnerScopedServerFinishesWithoutIssuesHavingReachedIt() throws Exception {
        server = StreamingCampaignServer.ownerScoped();
        int port = initializeWithAutomation();

        post(port, aliceComparingBob());
        JsonNode finished = awaitEnded(port);

        assertThat(finished.path("status").asText()).as(finished.toString()).isEqualTo("finished");
        assertThat(finished.path("issues")).isEmpty();
        assertThat(finished.path("requestsReached").asInt()).isPositive();
    }

    @Test
    void reportsNoCheckAccessBeforeOneIsLaunched() throws Exception {
        server = StreamingCampaignServer.vulnerable();
        int port = initializeWithAutomation();

        assertThat(get(port).statusCode()).isEqualTo(404);
    }

    private String aliceComparingBob() {
        return """
                {"endpoint":"%s","transport":"STREAMABLE_HTTP","auth":{"bearerToken":"%s"},"useBurpNetworking":false,
                 "identities":{"connectAs":{"name":"alice","privateMarker":"%s","ownedObjects":{"id":"%s"}},
                   "others":[{"name":"bob","role":"PEER","auth":{"bearerToken":"%s"},"privateMarker":"%s",
                              "ownedObjects":{"id":"%s"}}]}}
                """.formatted(server.endpoint(), StreamingCampaignServer.ALICE_TOKEN,
                StreamingCampaignServer.ALICE_MARKER, StreamingCampaignServer.ALICE_CAMPAIGN,
                StreamingCampaignServer.BOB_TOKEN, StreamingCampaignServer.BOB_MARKER,
                StreamingCampaignServer.BOB_CAMPAIGN);
    }

    private JsonNode awaitEnded(int port) {
        return await().atMost(RUN_BOUND).until(() -> McpObjectMapper.INSTANCE.readTree(get(port).body()),
                status -> List.of("finished", "cancelled", "stopped", "failed").contains(status.path("status").asText()));
    }

    private int initializeWithAutomation() {
        new McpScannerExtension(new TestAutomationWiring(new TestAutomationSwitch(Map.of(TestAutomationSwitch.PORT_PROPERTY, "0")::get)))
                .initialize(api);
        ArgumentCaptor<String> output = ArgumentCaptor.forClass(String.class);
        verify(api.logging(), atLeastOnce()).logToOutput(output.capture());
        return output.getAllValues().stream().map(LISTENING::matcher).filter(Matcher::matches)
                .map(matcher -> Integer.parseInt(matcher.group(1))).findFirst().orElseThrow();
    }

    private HttpResponse<String> post(int port, String body) throws Exception {
        return client.send(java.net.http.HttpRequest.newBuilder(uri(port))
                        .header("Content-Type", "application/json")
                        .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(int port) throws Exception {
        return client.send(java.net.http.HttpRequest.newBuilder(uri(port)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static URI uri(int port) {
        return URI.create("http://127.0.0.1:" + port + AutomationServer.CHECK_ACCESS_PATH);
    }

    private void routeThroughTheExtensionsHandler() throws Exception {
        HandlerRoutedBurpHttp burp = new HandlerRoutedBurpHttp(this::routedByTheExtensionsHandler,
                ClientCertificateBurpHttp.withoutClientCertificate());
        when(http.sendRequest(any(HttpRequest.class)))
                .thenAnswer(invocation -> burp.sendRequest(invocation.getArgument(0, HttpRequest.class)));
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> burp.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, RequestOptions.class)));
    }

    private HttpRequest routedByTheExtensionsHandler(HttpRequest request) {
        ArgumentCaptor<HttpHandler> handler = ArgumentCaptor.forClass(HttpHandler.class);
        verify(http, atLeastOnce()).registerHttpHandler(handler.capture());
        return handler.getAllValues().stream().filter(McpHttpHandler.class::isInstance).map(McpHttpHandler.class::cast)
                .findFirst().orElseThrow().route(request);
    }

    private static void renderRequestsAsImmutable() {
        when(ObjectFactoryLocator.FACTORY.httpRequest(any(HttpService.class), anyString()))
                .thenAnswer(call -> parsed(call.getArgument(0), call.getArgument(1)));
    }

    private static HttpRequest parsed(HttpService service, String raw) {
        String[] headAndBody = raw.split("\r\n\r\n", 2);
        String[] lines = headAndBody[0].split("\r\n");
        Map<String, String> headers = new LinkedHashMap<>();
        Arrays.stream(lines).skip(1).map(line -> line.split(": ", 2))
                .filter(header -> !List.of("content-length", "host").contains(header[0].toLowerCase(Locale.ROOT)))
                .forEach(header -> headers.put(header[0], header[1]));
        String url = "http://" + service.host() + ":" + service.port() + lines[0].split(" ")[1];
        return ImmutableHttpRequest.post(url, headers, headAndBody[1]);
    }
}
