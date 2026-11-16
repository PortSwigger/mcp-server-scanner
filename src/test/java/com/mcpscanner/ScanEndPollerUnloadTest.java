package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.audit.Audit;
import com.mcpscanner.automation.TestAutomationSwitch;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RenderedRequests;
import com.mcpscanner.testutil.ScriptedBurpHttp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScanEndPollerUnloadTest {

    private static final String ENDPOINT = "https://mcp.example.test/mcp";
    private static final Pattern LISTENING = Pattern.compile("Test automation listening on 127\\.0\\.0\\.1:(\\d+)");
    private static final String POLLER_THREAD = "mcp-scan-end-poller";

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private final Extension extension = mock(Extension.class);
    private final Http http = mock(Http.class);
    private final Audit audit = mock(Audit.class);
    private final PersistedObject savedSettings = InMemoryPersistedObject.create();
    private final ScriptedBurpHttp fakeServer = ScriptedBurpHttp.fakeMcpServer();

    @BeforeEach
    void stubMontoya() {
        MontoyaTestFactory.install();
        RenderedRequests.capture();
        when(api.extension()).thenReturn(extension);
        when(api.http()).thenReturn(http);
        when(api.persistence().extensionData()).thenReturn(savedSettings);
        when(api.scanner().startAudit(any())).thenReturn(audit);
        when(api.siteMap().issues()).thenReturn(List.of());
        when(audit.statusMessage()).thenReturn("scanning");
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> fakeServer.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, RequestOptions.class)));
    }

    @Test
    void unloadingAfterABurpAuditWasDetachedAtDisconnectLeavesNoScanEndPollerThreadAlive() throws Exception {
        Set<Thread> before = pollerThreads();
        int port = initializeWithAutomation();
        assertThat(launchBurpAudit(port).statusCode()).isEqualTo(200);
        assertThat(launchBurpAudit(port).statusCode()).isEqualTo(200);
        await().atMost(Duration.ofSeconds(3)).until(() -> pollerThreads().stream().anyMatch(thread -> !before.contains(thread)));

        unload();

        await().atMost(Duration.ofSeconds(3)).untilAsserted(() ->
                assertThat(pollerThreads().stream().filter(thread -> !before.contains(thread) && thread.isAlive()))
                        .isEmpty());
    }

    private void unload() {
        ArgumentCaptor<ExtensionUnloadingHandler> unloading = ArgumentCaptor.forClass(ExtensionUnloadingHandler.class);
        verify(extension, atLeastOnce()).registerUnloadingHandler(unloading.capture());
        unloading.getAllValues().forEach(ExtensionUnloadingHandler::extensionUnloaded);
    }

    private static Set<Thread> pollerThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(thread -> POLLER_THREAD.equals(thread.getName())).collect(Collectors.toSet());
    }

    private int initializeWithAutomation() {
        new McpScannerExtension(new TestAutomationWiring(new TestAutomationSwitch(Map.of(TestAutomationSwitch.PORT_PROPERTY, "0")::get)))
                .initialize(api);
        ArgumentCaptor<String> output = ArgumentCaptor.forClass(String.class);
        verify(api.logging(), atLeastOnce()).logToOutput(output.capture());
        return output.getAllValues().stream().map(LISTENING::matcher).filter(Matcher::matches)
                .map(matcher -> Integer.parseInt(matcher.group(1))).findFirst().orElseThrow();
    }

    private HttpResponse<String> launchBurpAudit(int port) throws Exception {
        return HttpClient.newHttpClient().send(java.net.http.HttpRequest
                .newBuilder(URI.create("http://127.0.0.1:" + port + "/scan-all"))
                .header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString("""
                        {"endpoint":"%s","transport":"STREAMABLE_HTTP","checks":["file-traversal"],
                         "useBurpNetworking":true}
                        """.formatted(ENDPOINT))).build(), HttpResponse.BodyHandlers.ofString());
    }
}
