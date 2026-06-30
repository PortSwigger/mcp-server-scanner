package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
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
import com.mcpscanner.checks.McpActiveToolArgumentRceCheck;
import com.mcpscanner.checks.registry.ManagedCheck;
import com.mcpscanner.scan.McpInsertionPointProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.awt.*;
import java.lang.reflect.Field;
import java.util.function.Supplier;

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

        // T-deadcheck: unauth-tool-discovery, resource-traversal, tool-arg-traversal and
        // tool-arg-rce moved PER_HOST -> PER_REQUEST. PER_HOST-only checks with no scan-start
        // hook were never invoked (the audit only drives the PER_REQUEST path); internal HostDedup
        // keeps each self-discovering battery single-fire per host.
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("unauth-tool-discovery")), eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("auth-bypass")), eq(ScanCheckType.PER_REQUEST));
        // T14: hidden-method moved to PER_REQUEST so it dispatches in
        // "Active Scan from captured request" mode (PER_HOST is silently skipped).
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("hidden-method")), eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("resource-traversal")), eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("oauth-token-validation")), eq(ScanCheckType.PER_HOST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("dns-rebinding")), eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("oauth-metadata-ssrf")), eq(ScanCheckType.PER_REQUEST));
        // dcr-misconfiguration and consent-page-reflected-xss are scan-start-only
        // ManagedScanStartChecks — they register no per-request scanner surface.
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("tool-arg-traversal")), eq(ScanCheckType.PER_REQUEST));
        verify(scanner).registerActiveScanCheck(argThat(activeManagedWithId("tool-arg-rce")), eq(ScanCheckType.PER_REQUEST));
        verify(scanner, times(9)).registerActiveScanCheck(any(ActiveScanCheck.class), any(ScanCheckType.class));
    }

    @Test
    void registersContentScannersAsPassiveChecks() {
        sut.initialize(api);

        verify(scanner).registerPassiveScanCheck(
                argThat(passiveManagedWithId("discovery-content-scanner")), eq(ScanCheckType.PER_HOST));
        verify(scanner).registerPassiveScanCheck(
                argThat(passiveManagedWithId("response-content-scanner")), eq(ScanCheckType.PER_HOST));
        verify(scanner, times(2)).registerPassiveScanCheck(any(PassiveScanCheck.class), any(ScanCheckType.class));
    }

    private static org.mockito.ArgumentMatcher<ActiveScanCheck> activeManagedWithId(String id) {
        return check -> matchesId(check, id);
    }

    private static org.mockito.ArgumentMatcher<PassiveScanCheck> passiveManagedWithId(String id) {
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
    void registersUnloadingHandler() {
        sut.initialize(api);

        verify(extension, atLeastOnce()).registerUnloadingHandler(any(ExtensionUnloadingHandler.class));
    }

    @Test
    void registersHttpHandler() {
        sut.initialize(api);

        verify(http).registerHttpHandler(any(HttpHandler.class));
    }

    @Test
    void logsSuccessMessage() {
        sut.initialize(api);

        verify(logging).logToOutput("MCP Server Scanner loaded successfully");
    }

    @Test
    void extensionLoadsCleanlyWhenCollaboratorFactoryThrows() throws Exception {
        // Burp Community Edition throws when api.collaborator() is
        // called. The extension must boot without propagating, must still
        // register the RCE check, and the wired supplier must return null
        // (not throw) when later invoked by the scanner.
        when(api.collaborator()).thenThrow(new IllegalStateException("Collaborator requires Burp Pro"));

        assertThatCode(() -> sut.initialize(api)).doesNotThrowAnyException();

        ArgumentCaptor<ActiveScanCheck> activeCheckCaptor = ArgumentCaptor.forClass(ActiveScanCheck.class);
        verify(scanner, atLeastOnce()).registerActiveScanCheck(activeCheckCaptor.capture(), any(ScanCheckType.class));

        McpActiveToolArgumentRceCheck rceCheck = activeCheckCaptor.getAllValues().stream()
                .filter(McpActiveToolArgumentRceCheck.class::isInstance)
                .map(McpActiveToolArgumentRceCheck.class::cast)
                .findFirst()
                .orElseThrow(() -> new AssertionError("RCE check not registered"));

        Supplier<CollaboratorClient> supplier = extractCollaboratorSupplier(rceCheck);
        assertThat(supplier).isNotNull();
        assertThatCode(supplier::get).doesNotThrowAnyException();
        assertThat(supplier.get()).isNull();
    }

    @SuppressWarnings("unchecked")
    private static Supplier<CollaboratorClient> extractCollaboratorSupplier(McpActiveToolArgumentRceCheck check)
            throws Exception {
        Field field = McpActiveToolArgumentRceCheck.class.getDeclaredField("collaboratorSupplier");
        field.setAccessible(true);
        return (Supplier<CollaboratorClient>) field.get(check);
    }
}
