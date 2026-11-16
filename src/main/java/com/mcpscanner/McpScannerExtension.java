package com.mcpscanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.mcpscanner.access.OwnerRequests;
import com.mcpscanner.client.servercard.ServerCardFetcher;
import com.mcpscanner.engine.McpScanEngine;
import com.mcpscanner.ui.BurpNetworkingPrompt;
import com.mcpscanner.ui.DestructiveScanPrompt;
import com.mcpscanner.ui.widgets.DialogOwner;
import com.mcpscanner.ui.IdentityDependencies;
import com.mcpscanner.ui.McpScannerTab;
import com.mcpscanner.ui.McpScannerTabDependencies;
import com.mcpscanner.ui.ServerConfigPanel;
import com.mcpscanner.ui.SettingsPanel;
import com.mcpscanner.ui.access.AccessServices;
import com.mcpscanner.ui.access.MiningDialogs;
import com.mcpscanner.ui.access.MiningServices;
import com.mcpscanner.ui.scans.MessageEditors;
import com.mcpscanner.ui.scans.ScansServices;
import com.mcpscanner.ui.scans.SwingDelay;
import com.mcpscanner.ui.scans.SwingTargetNavigator;
import com.mcpscanner.ui.engine.ConfirmedMcpOnlyScan;
import com.mcpscanner.ui.engine.McpOnlyScanMenu;
import com.mcpscanner.ui.identities.ReconnectPrompt;
import com.mcpscanner.ui.sendto.MontoyaSendToDestinations;
import com.mcpscanner.ui.sendto.SendToShortcuts;
import com.mcpscanner.ui.widgets.DaemonReadScheduler;
import com.mcpscanner.ui.widgets.UiReads;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

public class McpScannerExtension implements BurpExtension {

    private final ExtensionAutomation automation;

    public McpScannerExtension() {
        this(ExtensionAutomation.installed());
    }

    McpScannerExtension(ExtensionAutomation automation) {
        this.automation = automation;
    }

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(ExtensionMetadata.NAME);
        ExtensionFoundation foundation = ExtensionFoundation.create(api);
        ConnectionWiring connection = ConnectionWiring.create(api, foundation);
        OAuthWiring oauth = OAuthWiring.create(api, foundation, connection.burpHttp());
        IdentityWiring identities = IdentityWiring.create(api, foundation, connection, oauth);
        AccessWiring access = AccessWiring.create(foundation, connection, identities.listings(), identities.discovery());
        ScanFieldWiring fields = ScanFieldWiring.create(api, foundation);
        McpScanEngine engine = EngineWiring.create(api, foundation, connection.burpHttp(), fields.everyField());
        ScanningWiring scanning = ScanningWiring.create(api, foundation, connection, access, fields, engine,
                automation.instrumentation(), automation.launchRenderer());
        MiningWiring mining = MiningWiring.create(foundation, connection, access, scanning);
        RegistrationCleanupWiring registrationCleanup = RegistrationCleanupWiring.register(api, connection.burpHttp(), foundation.eventLog());
        connection.resetOnDisconnect(scanning.sessionResets());
        connection.resetOnDisconnect(oauth.sessionResets());
        connection.resetOnDisconnect(access.sessionResets());
        connection.resetOnDisconnect(mining.sessionResets());

        ShutdownHooks shutdown = new ShutdownHooks(api.logging()::logToError);
        DaemonReadScheduler uiReads = new DaemonReadScheduler();
        UiReads backgroundReads = UiReads.background(uiReads, foundation.eventLog()::debug);
        McpScannerTab tab = registerUiOnEdt(api, foundation, connection, scanning, oauth, identities,
                backgroundReads);
        AccessServices accessServices = accessServices(foundation, connection, identities, access, scanning)
                .withMining(miningServices(api, foundation, mining));
        ScansServices scansServices = scansServices(api, foundation, engine);
        onEdt(api, () -> {
            tab.installAccess(accessServices);
            tab.installScans(scansServices);
        });
        shutdown.add("MCP Scanner tab", tab::shutdown);
        shutdown.add("UI reads", uiReads::shutdown);
        EngineWiring.registerChecks(engine, scanning.checkRegistry(), shutdown);
        api.userInterface().registerContextMenuItemsProvider(new McpOnlyScanMenu(new ConfirmedMcpOnlyScan(
                access.invokedTools(), backgroundReads, tab.writeReplayApproval(),
                access.confirmations()::confirm, foundation.eventLog(), scanning.engineScans())));
        access.addShutdownHooks(shutdown);
        mining.addShutdownHooks(shutdown);
        connection.start(shutdown);
        scanning.addShutdownHooks(shutdown);
        automation.startIfSwitchedOn(api, foundation, connection, scanning, access, mining, shutdown);
        oauth.addShutdownHooks(shutdown);
        identities.addShutdownHooks(shutdown);
        registrationCleanup.addShutdownHooks(shutdown);
        shutdown.add("Collaborator watch", foundation.collaboratorWatch()::shutdown);
        shutdown.add("Event log", foundation.eventLog()::shutdown);
        api.extension().registerUnloadingHandler(shutdown);

        api.logging().logToOutput(ExtensionMetadata.NAME + " loaded successfully");
    }

    private static AccessServices accessServices(ExtensionFoundation foundation,
                                                 ConnectionWiring connection, IdentityWiring identities,
                                                 AccessWiring access, ScanningWiring scanning) {
        OwnerRequests requests = access.sendToOwnerRequests(connection, scanning);
        return new AccessServices(access.matrix(), access.runner(connection, scanning),
                requests, access.confirmations(), identities.discovery()::refreshAll,
                foundation.identities()::otherUserCount);
    }

    private static MiningServices miningServices(MontoyaApi api, ExtensionFoundation foundation, MiningWiring mining) {
        return new MiningServices(mining.mining(), mining.ownedValues(), foundation.identities()::identities,
                MiningDialogs.modal(dialogOwner(api)));
    }

    private static ScansServices scansServices(MontoyaApi api, ExtensionFoundation foundation, McpScanEngine engine) {
        return ScansServices.of(engine.history(),
                new SwingTargetNavigator(() -> api.userInterface().swingUtils().suiteFrame(), foundation.eventLog()::debug,
                        new SwingDelay()),
                MessageEditors.readOnly(api.userInterface()));
    }

    private static DialogOwner dialogOwner(MontoyaApi api) {
        return new DialogOwner(() -> api.userInterface().swingUtils().suiteFrame());
    }

    private static void onEdt(MontoyaApi api, Runnable task) {
        onEdt(api, () -> {
            task.run();
            return null;
        });
    }

    private static <T> T onEdt(MontoyaApi api, Supplier<T> task) {
        AtomicReference<T> result = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> result.set(task.get()));
        } catch (InvocationTargetException ex) {
            api.logging().logToError("Failed to set up the UI on the EDT: " + ex.getCause());
            throw new IllegalStateException(ex.getCause());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(ex);
        }
        return result.get();
    }

    private static McpScannerTab registerUiOnEdt(MontoyaApi api, ExtensionFoundation foundation,
                                                 ConnectionWiring connection, ScanningWiring scanning,
                                                 OAuthWiring oauth, IdentityWiring identities, UiReads uiReads) {
        return onEdt(api, () -> registerUi(api, foundation,
                tabDependencies(api, foundation, connection, scanning, oauth, identities, uiReads), connection));
    }

    private static McpScannerTabDependencies tabDependencies(MontoyaApi api, ExtensionFoundation foundation,
                                                             ConnectionWiring connection, ScanningWiring scanning,
                                                             OAuthWiring oauth, IdentityWiring identities,
                                                             UiReads uiReads) {
        return new McpScannerTabDependencies(connection.clientManager(), scanning.scanLauncher(),
                api.logging(), foundation.configStore(), scanning.checkRegistry(), foundation.checkSettings(),
                foundation.eventLog(), scanning.authHolder(), scanning.generationSettings(), scanning.scanModeSetting(),
                scanning.requestRenderer(),
                ServerConfigPanel.create(foundation.configStore(), oauth.authorizationFlow(), oauth.discoverer(),
                        oauth.authorizationGate()::reset, dialogOwner(api)),
                scanning.sendToConnections(), oauth.optionalGrants()::create, DestructiveScanPrompt.modal(dialogOwner(api)),
                BurpNetworkingPrompt.modal(dialogOwner(api)),
                new IdentityDependencies(foundation.identities(), identities.listings(), identities.discovery(),
                        foundation.toolCallRefusals(),
                        identities::credentialServices, ReconnectPrompt.modal(dialogOwner(api))),
                scanning.scanOwnerArguments(), uiReads, dialogOwner(api));
    }

    private static McpScannerTab registerUi(MontoyaApi api, ExtensionFoundation foundation,
                                            McpScannerTabDependencies dependencies, ConnectionWiring connection) {
        McpScannerTab tab = new McpScannerTab(dependencies);
        tab.setSendToDestinations(MontoyaSendToDestinations.create(api));
        tab.setSendToShortcuts(new SendToShortcuts(
                () -> api.burpSuite().exportUserOptionsAsJson(SendToShortcuts.HOTKEYS_PATH)));
        tab.setBurpSettingsOpener(api.userInterface()::openSettingsWindow);
        tab.setServerCardSource(new ServerCardFetcher(connection.burpHttp())::fetch);
        api.userInterface().registerSuiteTab(ExtensionMetadata.NAME, tab);
        SettingsPanel globalSettings = new SettingsPanel(foundation.configStore());
        api.userInterface().registerSettingsPanel(globalSettings.asBurpSettingsPanel());
        return tab;
    }
}
