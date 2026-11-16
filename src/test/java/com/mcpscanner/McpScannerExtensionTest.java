package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.burpsuite.BurpSuite;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Persistence;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.ui.UserInterface;
import com.mcpscanner.config.RedirectMode;
import com.mcpscanner.checks.registry.ManagedCheck;
import com.mcpscanner.proxy.McpHttpHandler;
import com.mcpscanner.scan.McpInsertionPointProvider;
import com.mcpscanner.scan.request.GeneratedRegistrationCleanupHandler;
import com.mcpscanner.ui.SettingsPanel;
import com.mcpscanner.ui.scans.ScansPanel;
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
import javax.swing.JComboBox;
import javax.swing.SwingUtilities;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class McpScannerExtensionTest {

    @Mock private MontoyaApi api;
    @Mock private Extension extension;
    @Mock private Scanner scanner;
    @Mock private BurpSuite burpSuite;
    @Mock private UserInterface userInterface;
    @Mock private Http http;
    @Mock private Logging logging;
    @Mock private Persistence persistence;
    @Mock private PersistedObject persistedObject;

    private McpScannerExtension sut;

    @BeforeEach
    void setUp() {
        when(api.extension()).thenReturn(extension);
        when(api.scanner()).thenReturn(scanner);
        lenient().when(api.burpSuite()).thenReturn(burpSuite);
        when(api.userInterface()).thenReturn(userInterface);
        when(api.http()).thenReturn(http);
        when(api.logging()).thenReturn(logging);
        when(api.persistence()).thenReturn(persistence);
        when(persistence.extensionData()).thenReturn(persistedObject);

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
