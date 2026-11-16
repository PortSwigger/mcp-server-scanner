package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import burp.api.montoya.scanner.audit.Audit;
import com.mcpscanner.automation.BuiltInTrafficSink;
import com.mcpscanner.automation.TestAutomationSwitch;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RenderedRequests;
import com.mcpscanner.testutil.ScriptedBurpHttp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TestAutomationWiringTest {

    private static final String ENDPOINT = "https://mcp.example.test/mcp";
    private static final Pattern LISTENING = Pattern.compile("Test automation listening on 127\\.0\\.0\\.1:(\\d+)");

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private final Extension extension = mock(Extension.class);
    private final Http http = mock(Http.class);
    private final Audit audit = mock(Audit.class);
    private final ScriptedBurpHttp fakeServer = ScriptedBurpHttp.fakeMcpServer();
    private final HttpClient client = HttpClient.newHttpClient();
    private RenderedRequests rendered;
    private PersistedObject settings;

    @BeforeEach
    void stubMontoya() {
        MontoyaTestFactory.install();
        rendered = RenderedRequests.capture();
        when(api.extension()).thenReturn(extension);
        when(api.http()).thenReturn(http);
        settings = InMemoryPersistedObject.create();
        when(api.persistence().extensionData()).thenReturn(settings);
        when(api.scanner().startAudit(any())).thenReturn(audit);
        when(api.siteMap().issues()).thenReturn(List.of());
        when(audit.statusMessage()).thenReturn("scanning");
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> fakeServer.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, RequestOptions.class)));
    }

    @AfterEach
    void unload() {
        ArgumentCaptor<ExtensionUnloadingHandler> unloading = ArgumentCaptor.forClass(ExtensionUnloadingHandler.class);
        verify(extension, atLeastOnce()).registerUnloadingHandler(unloading.capture());
        unloading.getAllValues().forEach(ExtensionUnloadingHandler::extensionUnloaded);
    }

    @Test
    void switchedOnScanAllConnectsAndAddsTheGeneratedRequestsToOneScannerAudit() throws Exception {
        int port = initializeWithAutomation();

        HttpResponse<String> launched = post(port, "/scan-all", """
                {"endpoint":"%s","transport":"STREAMABLE_HTTP","checks":["file-traversal"],"useBurpNetworking":true,
                 "seeds":[{"method":"tools/call","params":{"name":"echo","arguments":{"text":"seed"}}}]}
                """.formatted(ENDPOINT));

        assertThat(launched.statusCode()).as(launched.body()).isEqualTo(200);
        verify(audit, atLeastOnce()).addRequest(any(HttpRequest.class));
        assertThat(rendered.raw()).anySatisfy(raw -> assertThat(raw).contains("\"tools/call\"", "\"seed\""));
        assertThat(get(port, "/audit").body()).contains("\"status\":\"scanning\"");
        verify(http).registerHttpHandler(any(BuiltInTrafficSink.class));
    }

    @Test
    void scanAllHandsTheUsersToTheIdentityRegistryWithoutPersistingTheirSecrets() throws Exception {
        int port = initializeWithAutomation();

        HttpResponse<String> launched = post(port, "/scan-all", """
                {"endpoint":"%s","transport":"STREAMABLE_HTTP","checks":["session-binding"],
                 "auth":{"bearerToken":"alice-secret"},
                 "identities":{"connectAs":{"name":"alice","ownedObjects":{"text":"a-1"}},
                   "others":[{"name":"bob","role":"PEER","auth":{"bearerToken":"bob-secret"},
                              "privateMarker":"BOB_ONLY"}]}}
                """.formatted(ENDPOINT));

        assertThat(launched.statusCode()).as(launched.body()).isEqualTo(200);
        ArgumentCaptor<String> persisted = ArgumentCaptor.forClass(String.class);
        verify(settings, atLeastOnce()).setString(any(), persisted.capture());
        assertThat(persisted.getAllValues()).anySatisfy(value -> assertThat(value).contains("bob", "BOB_ONLY"))
                .noneSatisfy(value -> assertThat(value).containsAnyOf("alice-secret", "bob-secret"));
    }

    @Test
    void scanAllRefusesToConfirmAToolTheServerDoesNotList() throws Exception {
        int port = initializeWithAutomation();

        HttpResponse<String> launched = post(port, "/scan-all", """
                {"endpoint":"%s","transport":"STREAMABLE_HTTP","identities":{"confirmedWrites":["drop_tables"]}}
                """.formatted(ENDPOINT));

        assertThat(launched.statusCode()).isEqualTo(500);
        assertThat(launched.body()).contains("drop_tables");
    }

    @Test
    void switchedOnReportsNoAuditBeforeScanAll() throws Exception {
        int port = initializeWithAutomation();

        assertThat(get(port, "/audit").statusCode()).isEqualTo(404);
    }

    @Test
    void sendCanaryReusesOneHttp1ConnectionThroughTheExtensionsBurpHttp() throws Exception {
        int port = initializeWithAutomation();
        HttpRequestResponse http1Reply = mock(HttpRequestResponse.class, RETURNS_DEEP_STUBS);
        when(http1Reply.response().httpVersion()).thenReturn("HTTP/1.1");
        when(http1Reply.response().statusCode()).thenReturn((short) 200);
        when(http.sendRequest(any(HttpRequest.class))).thenReturn(http1Reply);
        when(http.sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), anyString())).thenReturn(http1Reply);

        HttpResponse<String> report = post(port, "/send-canary",
                "{\"url\":\"http://127.0.0.1:9/canary\",\"count\":3,\"concurrency\":1}");

        assertThat(report.statusCode()).as(report.body()).isEqualTo(200);
        verify(http).sendRequest(any(HttpRequest.class));
        verify(http, times(2)).sendRequest(any(HttpRequest.class), eq(HttpMode.HTTP_1), eq("mcp-scanner-http://127.0.0.1:9"));
    }

    @Test
    void switchedOffStartsNoAutomationServer() {
        new McpScannerExtension(new TestAutomationWiring(new TestAutomationSwitch(name -> null))).initialize(api);

        verify(http, org.mockito.Mockito.never()).registerHttpHandler(any(BuiltInTrafficSink.class));
        verify(api.logging(), org.mockito.Mockito.never())
                .logToOutput(argThat((String line) -> line.startsWith("Test automation")));
    }

    private int initializeWithAutomation() {
        new McpScannerExtension(new TestAutomationWiring(new TestAutomationSwitch(Map.of(TestAutomationSwitch.PORT_PROPERTY, "0")::get)))
                .initialize(api);
        ArgumentCaptor<String> output = ArgumentCaptor.forClass(String.class);
        verify(api.logging(), atLeastOnce()).logToOutput(output.capture());
        return output.getAllValues().stream().map(LISTENING::matcher).filter(Matcher::matches)
                .map(matcher -> Integer.parseInt(matcher.group(1))).findFirst().orElseThrow();
    }

    private HttpResponse<String> post(int port, String path, String body) throws Exception {
        return client.send(java.net.http.HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header("Content-Type", "application/json").POST(java.net.http.HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(int port, String path) throws Exception {
        return client.send(java.net.http.HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .GET().build(), HttpResponse.BodyHandlers.ofString());
    }
}
