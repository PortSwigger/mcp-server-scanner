package com.mcpscanner;

import com.mcpscanner.testutil.InMemoryPreferences;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.core.Version;
import burp.api.montoya.collaborator.Collaborator;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.ui.UserInterface;
import com.mcpscanner.config.RedirectMode;
import com.mcpscanner.http.BareRequests;
import com.mcpscanner.checks.registry.ManagedCheck;
import com.mcpscanner.proxy.McpHttpHandler;
import com.mcpscanner.scan.McpInsertionPointProvider;
import com.mcpscanner.scan.request.GeneratedRegistrationCleanupHandler;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.ui.SettingsPanel;
import com.mcpscanner.ui.access.AccessPanel;
import com.mcpscanner.ui.scans.ScansPanel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.awt.*;
import java.lang.reflect.Field;
import java.util.function.Supplier;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.AbstractButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class McpScannerExtensionTest {

    @Mock private MontoyaApi api;
    @Mock private Extension extension;
    @Mock private Scanner scanner;
    @Mock private BurpSuite burpSuite;
    @Mock private Version version;
    @Mock private UserInterface userInterface;
    @Mock private Http http;
    @Mock private Logging logging;
    @Mock private Persistence persistence;
    @Mock private PersistedObject persistedObject;

    private McpScannerExtension sut;

    @BeforeAll
    static void installMontoyaOutsideTheStrictStubbingSession() {
        MontoyaTestFactory.install();
    }

    @BeforeEach
    void setUp() {
        when(api.extension()).thenReturn(extension);
        when(api.scanner()).thenReturn(scanner);
        lenient().when(api.burpSuite()).thenReturn(burpSuite);
        when(burpSuite.version()).thenReturn(version);
        when(version.edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL);
        when(api.userInterface()).thenReturn(userInterface);
        when(api.http()).thenReturn(http);
        when(api.logging()).thenReturn(logging);
        when(api.persistence()).thenReturn(persistence);
        when(persistence.extensionData()).thenReturn(persistedObject);
        when(persistence.preferences()).thenReturn(new InMemoryPreferences());

        sut = new McpScannerExtension();
    }

    @Test
    void setsExtensionName() {
        sut.initialize(api);

        verify(extension).setName("MCP Server Scanner");
    }

    @Test
    void registersInsertionPointProvider() {
        sut.initialize(api);

        verify(scanner).registerInsertionPointProvider(any(McpInsertionPointProvider.class));
    }


    @Test
    void registersAllActiveScanChecks() {
        sut.initialize(api);

        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("jwt-validation")), eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("origin-host-admission")), eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("command-injection")),
                eq(ScanCheckType.PER_INSERTION_POINT));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("sql-injection")),
                eq(ScanCheckType.PER_INSERTION_POINT));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("oauth-refresh-grant")), eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("oauth-authorization-consent")),
                eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("downstream-route-escape")),
                eq(ScanCheckType.PER_INSERTION_POINT));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("outbound-request")), eq(ScanCheckType.PER_INSERTION_POINT));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("ssrf-filter-bypass")),
                eq(ScanCheckType.PER_INSERTION_POINT));
        verify(scanner, never()).registerActiveScanCheck(argThat(activeManagedWithId("crossidentityaccess")), any());
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("sibling-route-auth-parity")),
                eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("session-lifecycle")), eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("cross-client-response-leak")),
                eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("session-binding")),
                eq(ScanCheckType.PER_REQUEST));
        verify(scanner, times(0 + 4 + 16)).registerActiveScanCheck(any(ActiveScanCheck.class), any(ScanCheckType.class));
    }

    @Test
    void registersServiceDiscoveredCatalogChecksWithTheirKindsScanCheckType() {
        sut.initialize(api);

        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("fixture-reflected-marker")),
                eq(ScanCheckType.PER_INSERTION_POINT));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("fixture-resend-succeeds")),
                eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("fixture-server-banner")),
                eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("oauth-consent-structure-reflection")),
                eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("oauth-redirect-policy")),
                eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("unauthenticated-request-execution")),
                eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("file-traversal")),
                eq(ScanCheckType.PER_INSERTION_POINT));
    }

    @Test
    void registersNoPassiveScanChecks() {
        sut.initialize(api);

        verify(scanner, never()).registerPassiveScanCheck(any(PassiveScanCheck.class), any(ScanCheckType.class));
    }

    private static org.mockito.ArgumentMatcher<ActiveScanCheck> activeManagedWithId(String id) {
        return check -> matchesId(check, id);
    }

    private static boolean matchesId(Object check, String id) {
        return check instanceof ManagedCheck managed
                && id.equals(managed.descriptor().id());
    }

    @Test
    void registersSuiteTab() {
        sut.initialize(api);

        verify(userInterface).registerSuiteTab(eq("MCP Server Scanner"), any(Component.class));
    }

    @Test
    void theSuiteTabHoldsTheScansTab() {
        sut.initialize(api);

        ArgumentCaptor<Component> tab = ArgumentCaptor.forClass(Component.class);
        verify(userInterface).registerSuiteTab(eq("MCP Server Scanner"), tab.capture());
        assertThat(findComponent(tab.getValue(), ScansPanel.class)).isNotNull();
    }

    @Test
    void theSuiteTabHoldsTheCheckAccessTabWithCollectIds() {
        sut.initialize(api);

        ArgumentCaptor<Component> tab = ArgumentCaptor.forClass(Component.class);
        verify(userInterface).registerSuiteTab(eq("MCP Server Scanner"), tab.capture());
        AccessPanel access = findComponent(tab.getValue(), AccessPanel.class);
        assertThat(access).isNotNull();
        assertThat(SwingTree.descendants(access)).filteredOn(AbstractButton.class::isInstance)
                .map(button -> ((AbstractButton) button).getText()).contains("Collect IDs");
    }

    @Test
    void theRegisteredOutOfBandCheckReachesBurpCollaborator() {
        Collaborator collaborator = mock(Collaborator.class);
        when(api.collaborator()).thenReturn(collaborator);
        when(persistedObject.getBoolean(anyString())).thenReturn(null);
        sut.initialize(api);

        catchThrowable(() -> registeredCheck("outbound-request")
                .doCheck(toolsCallWithAUrlArgument(), urlArgument(), http));

        verify(collaborator).createClient();
    }

    private ActiveScanCheck registeredCheck(String id) {
        ArgumentCaptor<ActiveScanCheck> checks = ArgumentCaptor.forClass(ActiveScanCheck.class);
        verify(scanner, atLeastOnce()).registerActiveScanCheck(checks.capture(), any(ScanCheckType.class));
        return checks.getAllValues().stream().filter(activeManagedWithId(id)::matches).findFirst().orElseThrow();
    }

    private static HttpRequestResponse toolsCallWithAUrlArgument() {
        HttpRequest request = BareRequests.fromUrl("https://mcp.example.test/mcp")
                .withMethod("POST").withHeader("Content-Type", "application/json")
                .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                        + "\"params\":{\"name\":\"fetch\",\"arguments\":{\"url\":\"https://a.example\"}}}");
        return HttpRequestResponse.httpRequestResponse(request, null);
    }

    private static AuditInsertionPoint urlArgument() {
        AuditInsertionPoint point = mock(AuditInsertionPoint.class);
        lenient().when(point.name()).thenReturn("MCP field: params.arguments.url");
        lenient().when(point.baseValue()).thenReturn("https://a.example");
        return point;
    }

    @Test
    void registersGlobalSettingsPanelOnEdtThatPersistsChanges() throws Exception {
        AtomicReference<String> savedMode = new AtomicReference<>();
        when(persistedObject.getString(any(String.class))).thenAnswer(invocation ->
                "mcp.redirect.mode".equals(invocation.getArgument(0)) ? savedMode.get() : null);
        doAnswer(invocation -> {
            if ("mcp.redirect.mode".equals(invocation.getArgument(0))) {
                savedMode.set(invocation.getArgument(1));
            }
            return null;
        }).when(persistedObject).setString(any(String.class), any(String.class));
        doAnswer(invocation -> {
            assertThat(SwingUtilities.isEventDispatchThread()).isTrue();
            return null;
        }).when(userInterface).registerSettingsPanel(any(burp.api.montoya.ui.settings.SettingsPanel.class));

        sut.initialize(api);

        ArgumentCaptor<burp.api.montoya.ui.settings.SettingsPanel> globalCaptor =
                ArgumentCaptor.forClass(burp.api.montoya.ui.settings.SettingsPanel.class);
        verify(userInterface).registerSettingsPanel(globalCaptor.capture());

        SettingsPanel globalSettings = (SettingsPanel) globalCaptor.getValue().uiComponent();
        assertThat(globalCaptor.getValue().keywords()).contains("MCP");

        SwingUtilities.invokeAndWait(() ->
                findComponent(globalSettings, JComboBox.class).setSelectedItem(RedirectMode.ALWAYS));
        verify(persistedObject).setString("mcp.redirect.mode", "ALWAYS");
    }

    @Test
    void registersSettingsWithTheScanSections() {
        sut.initialize(api);

        ArgumentCaptor<burp.api.montoya.ui.settings.SettingsPanel> settings =
                ArgumentCaptor.forClass(burp.api.montoya.ui.settings.SettingsPanel.class);
        verify(userInterface).registerSettingsPanel(settings.capture());

        assertThat(settings.getValue().keywords()).contains("Collect IDs", "Extension scan", "Workers");
        assertThat(SwingTree.descendants((Container) settings.getValue().uiComponent()))
                .filteredOn(JLabel.class::isInstance).map(label -> ((JLabel) label).getText())
                .contains("Scan warnings", "Extension scan workers", "Collect IDs requests per user");
    }

    @Test
    void logsThatScanningIsEnabledInProfessional() {
        sut.initialize(api);

        verify(logging, times(1)).logToOutput(
                "Burp Suite Professional: scanning, Check access and Collect IDs are enabled");
    }

    private static <T extends Component> T findComponent(Component root, Class<T> componentType) {
        if (componentType.isInstance(root)) {
            return componentType.cast(root);
        }
        if (root instanceof Container container) {
            for (Component child : container.getComponents()) {
                T found = findComponent(child, componentType);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    @Test
    void registersUnloadingHandler() {
        sut.initialize(api);

        verify(extension, atLeastOnce()).registerUnloadingHandler(any(ExtensionUnloadingHandler.class));
    }

    @Test
    void registersOneUnloadingHandlerThatShutsEverythingDownCleanly() {
        sut.initialize(api);

        ArgumentCaptor<ExtensionUnloadingHandler> handler = ArgumentCaptor.forClass(ExtensionUnloadingHandler.class);
        verify(extension).registerUnloadingHandler(handler.capture());

        assertThatCode(handler.getValue()::extensionUnloaded).doesNotThrowAnyException();
        verify(logging, never()).logToError(argThat((String message) -> message.startsWith("Shutdown step")));
    }

    @Test
    void registersHttpHandler() {
        sut.initialize(api);

        verify(http).registerHttpHandler(any(McpHttpHandler.class));
    }

    @Test
    void registersTheHandlerThatDeletesClientsTheRegistrationFamilyCreated() {
        sut.initialize(api);

        verify(http).registerHttpHandler(any(GeneratedRegistrationCleanupHandler.class));
    }

    @Test
    void logsSuccessMessage() {
        sut.initialize(api);

        verify(logging).logToOutput("MCP Server Scanner loaded successfully");
    }

    @Test
    void extensionLoadsCleanlyWhenCollaboratorFactoryThrows() throws Exception {
        lenient().when(api.collaborator()).thenThrow(new IllegalStateException("Collaborator requires Burp Pro"));

        assertThatCode(() -> sut.initialize(api)).doesNotThrowAnyException();

        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("command-injection")),
                eq(ScanCheckType.PER_INSERTION_POINT));
        verify(api, never()).collaborator();
    }
}
