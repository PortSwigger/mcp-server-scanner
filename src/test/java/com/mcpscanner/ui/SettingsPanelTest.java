package com.mcpscanner.ui;

import com.mcpscanner.testutil.InMemoryPreferences;
import org.junit.jupiter.params.provider.EnumSource;

import org.junit.jupiter.params.ParameterizedTest;

import com.mcpscanner.client.BurpNetworkingSetting;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.config.RedirectMode;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.config.ResourceCap;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SettingsPanelTest {
    @Test
    void sharedSettingsStayInSyncAndPersistAcrossPanels() throws Exception {
        PersistedObject persisted = mock(PersistedObject.class);
        AtomicReference<String> savedMode = new AtomicReference<>();
        AtomicReference<Long> savedLimit = new AtomicReference<>();
        when(persisted.getString("mcp.redirect.mode")).thenAnswer(invocation -> savedMode.get());
        when(persisted.getLong("mcp.proxy.post_body_limit_bytes")).thenAnswer(invocation -> savedLimit.get());
        doAnswer(invocation -> {
            savedMode.set(invocation.getArgument(1));
            return null;
        }).when(persisted).setString(org.mockito.ArgumentMatchers.eq("mcp.redirect.mode"),
                org.mockito.ArgumentMatchers.anyString());
        doAnswer(invocation -> {
            savedLimit.set(invocation.getArgument(1));
            return null;
        }).when(persisted).setLong(org.mockito.ArgumentMatchers.eq("mcp.proxy.post_body_limit_bytes"),
                org.mockito.ArgumentMatchers.anyLong());
        doAnswer(invocation -> {
            savedLimit.set(null);
            return null;
        }).when(persisted).deleteLong("mcp.proxy.post_body_limit_bytes");

        ExtensionConfigStore config = new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class));
        SettingsPanel[] panels = new SettingsPanel[2];
        SwingUtilities.invokeAndWait(() -> {
            panels[0] = new SettingsPanel(config);
            panels[1] = new SettingsPanel(config);
            panels[0].redirectModeSelectorForTest().setSelectedItem(RedirectMode.ALWAYS);
            assertThat(panels[1].redirectModeSelectorForTest().getSelectedItem()).isEqualTo(RedirectMode.ALWAYS);
            panels[0].capFieldForTest(ResourceCap.PROXY_POST_BODY_BYTES).setText("2048");
            assertThat(panels[1].capFieldForTest(ResourceCap.PROXY_POST_BODY_BYTES).getText()).isEqualTo("2 KB");
        });
        SwingUtilities.invokeAndWait(() -> {
            assertThat(panels[1].redirectModeSelectorForTest().getSelectedItem()).isEqualTo(RedirectMode.ALWAYS);
            assertThat(panels[1].capFieldForTest(ResourceCap.PROXY_POST_BODY_BYTES).getText()).isEqualTo("2 KB");
            panels[1].redirectModeSelectorForTest().setSelectedItem(RedirectMode.SAME_ORIGIN);
            panels[1].capFieldForTest(ResourceCap.PROXY_POST_BODY_BYTES).setText("");
        });
        SwingUtilities.invokeAndWait(() -> {
            assertThat(panels[0].redirectModeSelectorForTest().getSelectedItem()).isEqualTo(RedirectMode.SAME_ORIGIN);
            assertThat(panels[0].capFieldForTest(ResourceCap.PROXY_POST_BODY_BYTES).getText())
                    .isEqualTo("32 MB");
        });
        assertThat(savedMode).hasValue("SAME_ORIGIN");
        assertThat(savedLimit).hasValue(null);
    }

    @Test
    void registersWithBurpAsItselfUnderSearchableKeywords() {
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(mock(PersistedObject.class), new InMemoryPreferences(), mock(Logging.class)));

        var burpPanel = panel.asBurpSettingsPanel();

        assertThat(burpPanel.uiComponent()).isSameAs(panel);
        assertThat(burpPanel.keywords()).contains("MCP", "Redirect", "Repeater", "Proxy");
    }

    @Test
    void fitsTheNarrowSidePanelWithoutClippingAnything() {
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(mock(PersistedObject.class), new InMemoryPreferences(), mock(Logging.class)));
        panel.offerBurpSettings(() -> { });
        panel.setSize(400, 900);
        for (int pass = 0; pass < 3; pass++) {
            layOut(panel);
        }

        com.mcpscanner.testutil.SwingTree.visibleDescendants(panel).forEach(component -> {
            java.awt.Point origin = javax.swing.SwingUtilities.convertPoint(component, 0, 0, panel);
            assertThat(origin.x + component.getWidth()).as(component.toString()).isLessThanOrEqualTo(400);
            assertThat(component.getWidth()).as(component.toString())
                    .isGreaterThanOrEqualTo(Math.min(component.getPreferredSize().width, 400 - origin.x));
        });
    }

    private static void layOut(java.awt.Container container) {
        container.doLayout();
        for (java.awt.Component child : container.getComponents()) {
            if (child instanceof java.awt.Container nested) {
                layOut(nested);
            }
        }
    }

    @Test
    void canOfferToOpenBurpsOwnSettingsWindow() {
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(mock(PersistedObject.class), new InMemoryPreferences(), mock(Logging.class)));
        java.util.concurrent.atomic.AtomicBoolean opened = new java.util.concurrent.atomic.AtomicBoolean();
        assertThat(panel.burpSettingsRowForTest().isVisible()).isFalse();

        panel.offerBurpSettings(() -> opened.set(true));
        panel.burpSettingsButtonForTest().doClick();

        assertThat(panel.burpSettingsRowForTest().isVisible()).isTrue();
        assertThat(panel.burpSettingsHintForTest()).contains("Settings > Extensions > MCP Server Scanner");
        assertThat(opened).isTrue();
    }

    @Test
    void loadsAndPersistsRedirectMode() {
        PersistedObject persisted = mock(PersistedObject.class);
        when(persisted.getString("mcp.redirect.mode")).thenReturn("SAME_ORIGIN");
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class)));

        assertThat(panel.redirectModeSelectorForTest().getSelectedItem()).isEqualTo(RedirectMode.SAME_ORIGIN);

        panel.redirectModeSelectorForTest().setSelectedItem(RedirectMode.ALWAYS);

        verify(persisted).setString("mcp.redirect.mode", "ALWAYS");
    }

    @Test
    void persistsExactPostBodyLimitAndBlankRestoresDefault() {
        PersistedObject persisted = mock(PersistedObject.class);
        when(persisted.getLong("mcp.proxy.post_body_limit_bytes")).thenReturn(1_048_577L);
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class)));

        assertThat(panel.capFieldForTest(ResourceCap.PROXY_POST_BODY_BYTES).getText()).isEqualTo("1048577 bytes");

        panel.capFieldForTest(ResourceCap.PROXY_POST_BODY_BYTES).setText("2048");
        verify(persisted).setLong("mcp.proxy.post_body_limit_bytes", 2048L);

        org.mockito.Mockito.clearInvocations(persisted);
        panel.capFieldForTest(ResourceCap.PROXY_POST_BODY_BYTES).setText("");
        verify(persisted).deleteLong("mcp.proxy.post_body_limit_bytes");
    }

    @Test
    void rejectsInvalidPostBodyLimitWithoutPersistingIt() {
        PersistedObject persisted = mock(PersistedObject.class);
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class)));

        panel.capFieldForTest(ResourceCap.PROXY_POST_BODY_BYTES).setText("-1");

        org.mockito.Mockito.verify(persisted, org.mockito.Mockito.never())
                .setLong(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyLong());
    }

    @Test
    void everyResourceCapShowsItsDefaultAndPersistsValidEdits() {
        PersistedObject persisted = mock(PersistedObject.class);
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class)));

        for (ResourceCap cap : ResourceCap.values()) {
            panel.capFieldForTest(cap).setText("42");
            verify(persisted).setLong(cap.key(), 42L);
        }
    }

    @Test
    void showsByteLimitsInHumanUnitsAndPageLimitsAsCounts() {
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(mock(PersistedObject.class), new InMemoryPreferences(), mock(Logging.class)));

        assertThat(panel.capFieldForTest(ResourceCap.PROXY_POST_BODY_BYTES).getText()).isEqualTo("32 MB");
        assertThat(panel.capFieldForTest(ResourceCap.SSE_PENDING_RESPONSE_BYTES).getText()).isEqualTo("64 MB");
        assertThat(panel.capFieldForTest(ResourceCap.DISCOVERY_TOTAL_BYTES).getText()).isEqualTo("256 MB");
        assertThat(panel.capFieldForTest(ResourceCap.DISCOVERY_MAX_PAGES).getText()).isEqualTo("100");
    }

    @Test
    void showsTheExtensionScanWorkerCountOutsideTheSafetyLimitsAndRejectsMoreThanFifty() {
        PersistedObject persisted = mock(PersistedObject.class);
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class)));

        assertThat(panel.capFieldForTest(ResourceCap.EXTENSION_SCAN_WORKERS).getText()).isEqualTo("10");

        panel.capFieldForTest(ResourceCap.EXTENSION_SCAN_WORKERS).setText("51");

        verify(persisted, org.mockito.Mockito.never()).setLong(ResourceCap.EXTENSION_SCAN_WORKERS.key(), 51L);
        assertThat(panel.capStatusForTest(ResourceCap.EXTENSION_SCAN_WORKERS).getText()).contains("1 to 50");
    }

    @Test
    void persistsAByteLimitTypedWithAUnitAsBytes() {
        PersistedObject persisted = mock(PersistedObject.class);
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class)));

        panel.capFieldForTest(ResourceCap.DISCOVERY_TOTAL_BYTES).setText("512 MB");

        verify(persisted).setLong(ResourceCap.DISCOVERY_TOTAL_BYTES.key(), 512L * 1024 * 1024);
    }

    @Test
    void anInvalidByteLimitHintSuggestsUnitsAndNamesTheDefault() {
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(mock(PersistedObject.class), new InMemoryPreferences(), mock(Logging.class)));

        panel.capFieldForTest(ResourceCap.PROXY_POST_BODY_BYTES).setText("lots");

        assertThat(panel.capStatusForTest(ResourceCap.PROXY_POST_BODY_BYTES).getText())
                .contains("32 MB").contains("512 KB");
    }

    @ParameterizedTest
    @EnumSource(RedirectMode.class)
    void theRedirectHelpExplainsTheSelectedOption(RedirectMode mode) {
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(mock(PersistedObject.class), new InMemoryPreferences(), mock(Logging.class)));

        panel.redirectModeSelectorForTest().setSelectedItem(mode);

        assertThat(panel.redirectExplanationForTest()).isEqualTo(mode.description());
    }

    @Test
    void rejectsZeroResourceCapWithVisibleHintAndWithoutPersistingIt() {
        PersistedObject persisted = mock(PersistedObject.class);
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class)));

        panel.capFieldForTest(ResourceCap.DISCOVERY_MAX_PAGES).setText("0");

        verify(persisted, org.mockito.Mockito.never()).setLong(ResourceCap.DISCOVERY_MAX_PAGES.key(), 0L);
        assertThat(panel.capStatusForTest(ResourceCap.DISCOVERY_MAX_PAGES).getText()).contains("whole number");
    }

    @Test
    void serverPingCheckboxDefaultsOnAndPersistsWhenCleared() throws Exception {
        PersistedObject persisted = mock(PersistedObject.class);
        AtomicReference<Boolean> saved = new AtomicReference<>();
        when(persisted.getBoolean("mcp.server_pings.answer")).thenAnswer(invocation -> saved.get());
        doAnswer(invocation -> {
            saved.set(invocation.getArgument(1));
            return null;
        }).when(persisted).setBoolean(org.mockito.ArgumentMatchers.eq("mcp.server_pings.answer"),
                org.mockito.ArgumentMatchers.anyBoolean());
        ExtensionConfigStore config = new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class));
        SettingsPanel[] panel = new SettingsPanel[1];

        SwingUtilities.invokeAndWait(() -> {
            panel[0] = new SettingsPanel(config);
            assertThat(panel[0].serverPingsCheckboxForTest().isSelected()).isTrue();
            assertThat(panel[0].serverPingsCheckboxForTest().getText()).isEqualTo("Answer server pings");
            panel[0].serverPingsCheckboxForTest().doClick();
        });

        assertThat(saved).hasValue(false);
        assertThat(config.answerServerPings()).isFalse();
    }

    @Test
    void burpNetworkingCheckboxDefaultsOnAndPersistsWhenCleared() throws Exception {
        PersistedObject persisted = mock(PersistedObject.class);
        AtomicReference<Boolean> saved = new AtomicReference<>();
        when(persisted.getBoolean("mcp.networking.use_burp")).thenAnswer(invocation -> saved.get());
        doAnswer(invocation -> {
            saved.set(invocation.getArgument(1));
            return null;
        }).when(persisted).setBoolean(org.mockito.ArgumentMatchers.eq("mcp.networking.use_burp"),
                org.mockito.ArgumentMatchers.anyBoolean());
        ExtensionConfigStore config = new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class));
        SettingsPanel[] panel = new SettingsPanel[1];

        SwingUtilities.invokeAndWait(() -> {
            panel[0] = new SettingsPanel(config);
            assertThat(panel[0].burpNetworkingCheckboxForTest().isSelected()).isTrue();
            assertThat(panel[0].burpNetworkingCheckboxForTest().getText())
                    .isEqualTo(BurpNetworkingSetting.NAME);
            panel[0].burpNetworkingCheckboxForTest().doClick();
        });

        assertThat(saved).hasValue(false);
        assertThat(config.useBurpNetworking()).isFalse();
    }

    @Test
    void burpNetworkingExplanationNamesClientCertificatesAndThePingTradeOff() {
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(mock(PersistedObject.class), new InMemoryPreferences(), mock(Logging.class)));

        assertThat(panel.burpNetworkingExplanationForTest())
                .contains("client TLS certificates")
                .contains("ping");
    }

    @Test
    void burpNetworkingExplanationSaysTheChangeAppliesToNewRequests() {
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(mock(PersistedObject.class), new InMemoryPreferences(), mock(Logging.class)));

        assertThat(panel.burpNetworkingExplanationForTest()).contains("Changes apply from the next request");
    }

    @Test
    void sendToAuthenticationCheckboxDefaultsOffPersistsAndFollowsLiveChanges() throws Exception {
        PersistedObject persisted = mock(PersistedObject.class);
        AtomicReference<Boolean> saved = new AtomicReference<>();
        when(persisted.getBoolean("mcp.sendto.handle_auth")).thenAnswer(invocation -> saved.get());
        doAnswer(invocation -> {
            saved.set(invocation.getArgument(1));
            return null;
        }).when(persisted).setBoolean(org.mockito.ArgumentMatchers.eq("mcp.sendto.handle_auth"),
                org.mockito.ArgumentMatchers.anyBoolean());
        ExtensionConfigStore config = new ExtensionConfigStore(persisted, new InMemoryPreferences(), mock(Logging.class));
        SettingsPanel[] panels = new SettingsPanel[2];

        SwingUtilities.invokeAndWait(() -> {
            panels[0] = new SettingsPanel(config);
            panels[1] = new SettingsPanel(config);
            assertThat(panels[0].sendToAuthenticationCheckboxForTest().isSelected()).isFalse();
            panels[0].sendToAuthenticationCheckboxForTest().doClick();
        });
        SwingUtilities.invokeAndWait(() ->
                assertThat(panels[1].sendToAuthenticationCheckboxForTest().isSelected()).isTrue());

        assertThat(saved).hasValue(true);
        assertThat(config.handleSendToAuthentication()).isTrue();
    }

    @Test
    void sendToAuthenticationExplainsBothSidesAndNamesTheMarkerHeader() {
        SettingsPanel panel = new SettingsPanel(new ExtensionConfigStore(mock(PersistedObject.class), new InMemoryPreferences(), mock(Logging.class)));

        assertThat(panel.sendToAuthenticationCheckboxForTest().getText())
                .isEqualTo("Handle auth and sessions in Burp tools");
        assertThat(panel.sendToAuthenticationExplanationForTest())
                .contains("X-Mcp-Scanner-Audit-Capability")
                .contains("renewing an expired OAuth token")
                .contains("Off: requests go straight to the server");
    }

    @Test
    void resettingScanWarningsClearsDontAskAgainForEveryServerAndSaysHowMany() {
        ExtensionConfigStore configStore = com.mcpscanner.testutil.InMemoryPersistedObject.configStore();
        configStore.setDontAskAgain("https://one.example/mcp", true);
        configStore.setDontAskAgain("https://two.example/mcp", true);
        SettingsPanel panel = new SettingsPanel(configStore);

        panel.resetScanWarningsButtonForTest().doClick();

        assertThat(configStore.dontAskAgain("https://one.example/mcp")).isFalse();
        assertThat(configStore.dontAskAgain("https://two.example/mcp")).isFalse();
        assertThat(panel.scanWarningsStatusForTest().getText()).isEqualTo("Scan warnings turned back on for 2 servers.");
    }

    @Test
    void resettingScanWarningsWithNothingSetSaysSo() {
        SettingsPanel panel = new SettingsPanel(com.mcpscanner.testutil.InMemoryPersistedObject.configStore());

        panel.resetScanWarningsButtonForTest().doClick();

        assertThat(panel.scanWarningsStatusForTest().getText()).startsWith("No server had");
    }

    @Test
    void savingAsMyDefaultsCarriesTheseSettingsIntoANewProject() {
        InMemoryPreferences preferences = new InMemoryPreferences();
        ExtensionConfigStore configStore = configStoreFor(preferences);
        configStore.setRedirectMode(RedirectMode.SAME_ORIGIN);
        SettingsPanel panel = new SettingsPanel(configStore);

        panel.saveUserDefaultsButtonForTest().doClick();

        assertThat(configStoreFor(preferences).redirectMode()).isEqualTo(RedirectMode.SAME_ORIGIN);
        assertThat(panel.userDefaultsStatusForTest().getText()).isEqualTo(UserDefaultsSettings.SAVED);
    }

    @Test
    void resettingMyDefaultsSendsNewProjectsBackToBuiltInDefaults() {
        InMemoryPreferences preferences = new InMemoryPreferences();
        preferences.setString("mcp.redirect.mode", RedirectMode.SAME_ORIGIN.name());
        SettingsPanel panel = new SettingsPanel(configStoreFor(preferences));

        panel.resetUserDefaultsButtonForTest().doClick();

        assertThat(configStoreFor(preferences).redirectMode()).isEqualTo(RedirectMode.METHOD_PRESERVING_SAME_ORIGIN);
        assertThat(panel.userDefaultsStatusForTest().getText()).isEqualTo(UserDefaultsSettings.CLEARED);
    }

    @Test
    void theDefaultsControlsShowWithoutScanningToo() {
        SettingsPanel panel = new SettingsPanel(com.mcpscanner.testutil.InMemoryPersistedObject.configStore(),
                SettingsScope.WITHOUT_SCANNING);

        assertThat(panel.saveUserDefaultsButtonForTest().getText()).isEqualTo(UserDefaultsSettings.SAVE);
        assertThat(panel.resetUserDefaultsButtonForTest().getText()).isEqualTo(UserDefaultsSettings.RESET);
    }

    @Test
    void withoutScanningTheDefaultsExplanationNamesNoScanningSetting() {
        SettingsPanel panel = new SettingsPanel(com.mcpscanner.testutil.InMemoryPersistedObject.configStore(),
                SettingsScope.WITHOUT_SCANNING);

        assertThat(panel.userDefaultsExplanationForTest())
                .contains("redirect", "OAuth redirect port", "client identity")
                .doesNotContain("scan mode", "checks", "request families", "fuzzing", "Collect IDs", "worker",
                        "tool choices", "write-tool");
    }

    @Test
    void withScanningTheDefaultsExplanationNamesTheScanningSettings() {
        SettingsPanel panel = new SettingsPanel(com.mcpscanner.testutil.InMemoryPersistedObject.configStore(),
                SettingsScope.WITH_SCANNING);

        assertThat(panel.userDefaultsExplanationForTest())
                .contains("scan mode", "checks", "request families", "_meta fuzzing", "Collect IDs passes", "worker",
                        "tool choices", "write-tool opt-ins");
    }

    private static ExtensionConfigStore configStoreFor(InMemoryPreferences preferences) {
        return new ExtensionConfigStore(com.mcpscanner.testutil.InMemoryPersistedObject.create(), preferences,
                mock(Logging.class));
    }
}
