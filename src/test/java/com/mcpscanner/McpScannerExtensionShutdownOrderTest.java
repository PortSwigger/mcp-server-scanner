package com.mcpscanner;

import com.mcpscanner.testutil.InMemoryPreferences;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.Http;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class McpScannerExtensionShutdownOrderTest {

    private final MontoyaApi api = mock(MontoyaApi.class, RETURNS_DEEP_STUBS);
    private final Extension extension = mock(Extension.class);
    private ShutdownHooks shutdown;

    @BeforeEach
    void loadInProfessional() {
        MontoyaTestFactory.install();
        when(api.extension()).thenReturn(extension);
        when(api.http()).thenReturn(mock(Http.class));
        PersistedObject savedSettings = InMemoryPersistedObject.create();
        when(api.persistence().extensionData()).thenReturn(savedSettings);
        when(api.persistence().preferences()).thenReturn(new InMemoryPreferences());
        when(api.burpSuite().version().edition()).thenReturn(BurpSuiteEdition.PROFESSIONAL);

        new McpScannerExtension(ExtensionAutomation.NONE).initialize(api);

        ArgumentCaptor<ExtensionUnloadingHandler> unloading = ArgumentCaptor.forClass(ExtensionUnloadingHandler.class);
        verify(extension).registerUnloadingHandler(unloading.capture());
        shutdown = (ShutdownHooks) unloading.getValue();
    }

    @AfterEach
    void unload() {
        shutdown.extensionUnloaded();
    }

    @Test
    void professionalStopsEveryWorkerItStartedInOrder() {
        assertThat(shutdown.names()).containsExactly(
                "MCP Scanner tab", "UI reads", "extension scan engine", "Check access", "Collecting IDs",
                "Browser consent check",
                "MCP client", "SSE proxy", "Burp HTTP transport", "Scan end poller",
                "OAuth callback listeners", "DNS resolver",
                "Identity discovery", "Identity sign-in", "Identity credentials",
                "Registration cleanup worker", "Retained registration cleanup", "Abandoned client summary",
                "Collaborator watch", "Event log");
    }
}
