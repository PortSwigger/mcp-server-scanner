package com.mcpscanner;

import com.mcpscanner.testutil.InMemoryPreferences;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.settings.SettingsPanel;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.config.AuthTypeNames;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.discovery.IdentityDiscoveryService;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.proxy.McpHttpHandler;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ScriptedBurpHttp;
import com.mcpscanner.testutil.SwingTree;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.stubbing.Answer;

import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class McpScannerExtensionCommunityTest {

    private static final String ENDPOINT = "https://mcp.example.test/mcp";
    private static final Duration CONNECT_BOUND = Duration.ofSeconds(10);

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private final Extension extension = mock(Extension.class);
    private final Http http = mock(Http.class);
    private final UserInterface userInterface = mock(UserInterface.class, RETURNS_DEEP_STUBS);
    private final List<String> forbiddenCalls = new CopyOnWriteArrayList<>();
    private final List<String> output = new CopyOnWriteArrayList<>();
    private final List<String> errors = new CopyOnWriteArrayList<>();
    private final ScriptedBurpHttp fakeServer = ScriptedBurpHttp.fakeMcpServer();
    private MockedConstruction<IdentityDiscoveryService> discoveryServices;

    @BeforeEach
    void loadInCommunity() {
        MontoyaTestFactory.install();
        when(api.extension()).thenReturn(extension);
        when(api.http()).thenReturn(http);
        when(http.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenAnswer(invocation -> fakeServer.sendRequest(invocation.getArgument(0, HttpRequest.class),
                        invocation.getArgument(1, RequestOptions.class)));
        when(api.userInterface()).thenReturn(userInterface);
        Logging logging = recordingLogging();
        when(api.logging()).thenReturn(logging);
        PersistedObject savedSettings = InMemoryPersistedObject.create();
        saveAConnectionWithAComparedUser(savedSettings, logging);
        when(api.persistence().extensionData()).thenReturn(savedSettings);
        when(api.persistence().preferences()).thenReturn(new InMemoryPreferences());
        when(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.COMMUNITY_EDITION);
        when(api.burpSuite().taskExecutionEngine()).thenAnswer(forbidden("taskExecutionEngine()"));
        when(api.scanner()).thenAnswer(forbidden("scanner()"));
        when(api.collaborator()).thenAnswer(forbidden("collaborator()"));
        when(api.siteMap()).thenAnswer(forbidden("siteMap()"));
        discoveryServices = mockConstruction(IdentityDiscoveryService.class);

        new McpScannerExtension().initialize(api);
    }

    @AfterEach
    void stopWatchingConstructions() {
        discoveryServices.close();
    }

    @Test
    void loadsWithTheSuiteTabAndSettingsPanel() {
        verify(userInterface).registerSuiteTab(eq(ExtensionMetadata.NAME), any(Component.class));
        verify(userInterface).registerSettingsPanel(any(SettingsPanel.class));
        assertThat(output).contains(ExtensionMetadata.NAME + " loaded successfully");
    }

    @Test
    void registersSettingsWithoutTheScanSections() {
        ArgumentCaptor<SettingsPanel> settings = ArgumentCaptor.forClass(SettingsPanel.class);
        verify(userInterface).registerSettingsPanel(settings.capture());

        assertThat(settings.getValue().keywords()).doesNotContain("Collect IDs", "Extension scan", "Workers");
        assertThat(SwingTree.descendants((Container) settings.getValue().uiComponent()))
                .filteredOn(JLabel.class::isInstance).map(label -> ((JLabel) label).getText())
                .doesNotContain("Scan warnings", "Extension scan workers", "Collect IDs requests per user");
    }

    @Test
    void logsThatScanningIsDisabledInCommunity() {
        assertThat(output).containsOnlyOnce(
                "Burp Suite Community Edition: scanning, Check access and Collect IDs are disabled");
    }

    @Test
    void neverReachesTheScannerCollaboratorSiteMapOrTaskEngine() {
        assertThat(forbiddenCalls).isEmpty();
    }

    @Test
    void registersOnlyTheMcpHttpHandler() {
        ArgumentCaptor<HttpHandler> handlers = ArgumentCaptor.forClass(HttpHandler.class);
        verify(http).registerHttpHandler(handlers.capture());

        assertThat(handlers.getAllValues()).singleElement().isInstanceOf(McpHttpHandler.class);
    }

    @Test
    void registersNoContextMenu() {
        verify(userInterface, never()).registerContextMenuItemsProvider(any(ContextMenuItemsProvider.class));
    }

    @Test
    void logsNothingAboutBurpAudits() {
        assertThat(output).noneMatch(line -> line.contains("Burp audits"));
    }

    @Test
    void connectingWithASavedComparedUserBuildsNoComparedUserDiscovery() throws Exception {
        clickConnect();

        await().atMost(CONNECT_BOUND).untilAsserted(() -> verify(http, atLeastOnce())
                .sendRequest(argThat(request -> request.bodyToString().contains("\"tools/list\"")),
                        any(RequestOptions.class)));
        assertThat(discoveryServices.constructed()).isEmpty();
    }

    @Test
    void unloadsCleanly() {
        ArgumentCaptor<ExtensionUnloadingHandler> unloading = ArgumentCaptor.forClass(ExtensionUnloadingHandler.class);
        verify(extension).registerUnloadingHandler(unloading.capture());

        assertThatCode(unloading.getValue()::extensionUnloaded).doesNotThrowAnyException();
        assertThat(errors).noneMatch(message -> message.startsWith("Shutdown step"));
        assertThat(forbiddenCalls).isEmpty();
    }

    private <T> Answer<T> forbidden(String call) {
        return invocation -> {
            forbiddenCalls.add(call);
            throw new AssertionError("Community must not call api." + call);
        };
    }

    private Logging recordingLogging() {
        Logging logging = mock(Logging.class);
        doAnswer(invocation -> output.add(invocation.getArgument(0))).when(logging).logToOutput(anyString());
        doAnswer(invocation -> errors.add(invocation.getArgument(0))).when(logging).logToError(anyString());
        return logging;
    }

    private static void saveAConnectionWithAComparedUser(PersistedObject savedSettings, Logging logging) {
        ExtensionConfigStore config = new ExtensionConfigStore(savedSettings, new InMemoryPreferences(), logging);
        config.setEndpoint(ENDPOINT);
        config.setTransport(TransportType.MODERN_HTTP.name());
        config.setAuthType(AuthTypeNames.NONE);
        new IdentityRegistry(new IdentityStore(config, new McpEventLog(logging)))
                .add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
    }

    private void clickConnect() throws Exception {
        ArgumentCaptor<Component> tab = ArgumentCaptor.forClass(Component.class);
        verify(userInterface).registerSuiteTab(eq(ExtensionMetadata.NAME), tab.capture());
        SwingUtilities.invokeAndWait(() -> SwingTree.button((Container) tab.getValue(), "Connect").doClick());
    }
}
