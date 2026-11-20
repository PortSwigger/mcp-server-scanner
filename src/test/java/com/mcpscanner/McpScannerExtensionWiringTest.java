package com.mcpscanner;

import com.mcpscanner.testutil.InMemoryPreferences;
import com.mcpscanner.proxy.McpHttpHandler;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ScanProxyClient;
import com.mcpscanner.testutil.ScriptedBurpHttp;
import com.mcpscanner.testutil.SwingTree;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;

import javax.swing.JMenuItem;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static com.mcpscanner.testutil.ScannerRequestToBeSent.sentinelCarryingScannerRequestTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.atMostOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class McpScannerExtensionWiringTest {

    private static final String ENDPOINT = "https://mcp.example.test/mcp";
    private static final Duration CONNECT_BOUND = Duration.ofSeconds(10);

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private final Extension extension = mock(Extension.class);
    private final Http http = mock(Http.class);
    private final PersistedObject savedSettings = mock(PersistedObject.class);
    private final ScriptedBurpHttp fakeServer = ScriptedBurpHttp.fakeMcpServer();

    @BeforeEach
    void stubMontoya() {
        MontoyaTestFactory.install();
        when(api.extension()).thenReturn(extension);
        when(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL);
        when(api.http()).thenReturn(http);
        when(api.persistence().extensionData()).thenReturn(savedSettings);
        when(api.persistence().preferences()).thenReturn(new InMemoryPreferences());
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

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void connectGoesThroughBurp(TransportType transport) throws Exception {
        initializeWithSavedConnection(transport);

        clickConnect();

        await().atMost(CONNECT_BOUND).untilAsserted(() -> verify(http, atLeastOnce())
                .sendRequest(argThat(request -> isCallTo(request, "tools/list")), any(RequestOptions.class)));
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void scannerToolsCallPostedToTheLocalProxyIsForwardedUpstreamThroughBurp(TransportType transport)
            throws Exception {
        initializeWithSavedConnection(transport);
        clickConnect();
        int proxyPort = await().atMost(CONNECT_BOUND).until(this::proxyPortScannerRequestsAreReroutedTo,
                Optional::isPresent).orElseThrow();

        int status = ScanProxyClient.sendScannerToolsCall(proxyPort, "echo").statusCode();

        assertThat(status).isEqualTo(200);
        verify(http).sendRequest(argThat(request -> isCallTo(request, "tools/call") && carriesNoSentinel(request)),
                any(RequestOptions.class));
    }

    @Test
    void clickingTheMcpOnlyScanMenuStartsAnEngineScan() {
        initializeWithSavedConnection(TransportType.STREAMABLE_HTTP);

        ((JMenuItem) registeredContextMenu().provideMenuItems(eventSelecting(unansweredRequest())).get(0))
                .doClick();

        verify(api.logging(), timeout(5_000)).logToOutput(startsWith("Extension scan started — 1 request, "));
    }

    private void initializeWithSavedConnection(TransportType transport) {
        when(savedSettings.getString("mcp.endpoint")).thenReturn(ENDPOINT);
        when(savedSettings.getString("mcp.transport")).thenReturn(transport.name());
        when(savedSettings.getString("mcp.auth.type")).thenReturn("None");
        when(savedSettings.getBoolean("mcp.networking.use_burp")).thenReturn(null);
        new McpScannerExtension().initialize(api);
    }

    private ContextMenuItemsProvider registeredContextMenu() {
        ArgumentCaptor<ContextMenuItemsProvider> menu = ArgumentCaptor.forClass(ContextMenuItemsProvider.class);
        verify(api.userInterface()).registerContextMenuItemsProvider(menu.capture());
        return menu.getValue();
    }

    private static ContextMenuEvent eventSelecting(HttpRequestResponse selected) {
        ContextMenuEvent event = mock(ContextMenuEvent.class);
        when(event.selectedRequestResponses()).thenReturn(List.of(selected));
        return event;
    }

    private static HttpRequestResponse unansweredRequest() {
        HttpRequest request = mock(HttpRequest.class);
        when(request.url()).thenReturn(ENDPOINT);
        HttpRequestResponse selected = mock(HttpRequestResponse.class);
        when(selected.request()).thenReturn(request);
        return selected;
    }

    private void clickConnect() throws Exception {
        ArgumentCaptor<Component> tab = ArgumentCaptor.forClass(Component.class);
        verify(api.userInterface()).registerSuiteTab(eq(ExtensionMetadata.NAME), tab.capture());
        SwingUtilities.invokeAndWait(() -> SwingTree.button((Container) tab.getValue(), "Connect").doClick());
    }

    private Optional<Integer> proxyPortScannerRequestsAreReroutedTo() {
        HttpRequestToBeSent scannerRequest = sentinelCarryingScannerRequestTo(URI.create(ENDPOINT));
        registeredHttpHandler().handleHttpRequestToBeSent(scannerRequest);
        ArgumentCaptor<HttpService> rerouted = ArgumentCaptor.forClass(HttpService.class);
        verify(scannerRequest, atMostOnce()).withService(rerouted.capture());
        return rerouted.getAllValues().stream().findFirst().map(HttpService::port);
    }

    private HttpHandler registeredHttpHandler() {
        ArgumentCaptor<HttpHandler> handler = ArgumentCaptor.forClass(HttpHandler.class);
        verify(http, atLeastOnce()).registerHttpHandler(handler.capture());
        return handler.getAllValues().stream().filter(McpHttpHandler.class::isInstance).findFirst().orElseThrow();
    }

    private static boolean isCallTo(HttpRequest request, String method) {
        return ENDPOINT.equals(request.url()) && request.bodyToString().contains("\"" + method + "\"");
    }

    private static boolean carriesNoSentinel(HttpRequest request) {
        return request.headers().stream()
                .noneMatch(header -> header.name().toLowerCase(Locale.ROOT).startsWith("x-mcp-scanner-"));
    }
}
