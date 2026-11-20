package com.mcpscanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.access.OwnerRequests;
import com.mcpscanner.access.WriteReplayApproval;
import com.mcpscanner.client.servercard.ServerCardFetcher;
import com.mcpscanner.engine.McpScanEngine;
import com.mcpscanner.identity.discovery.ComparedDiscovery;
import com.mcpscanner.identity.discovery.IdentityListings;
import com.mcpscanner.ui.BurpNetworkingPrompt;
import com.mcpscanner.ui.DestructiveScanPrompt;
import com.mcpscanner.ui.widgets.DialogOwner;
import com.mcpscanner.ui.IdentityDependencies;
import com.mcpscanner.ui.McpScannerTab;
import com.mcpscanner.ui.McpScannerTabDependencies;
import com.mcpscanner.ui.ScanServices;
import com.mcpscanner.ui.ServerConfigPanel;
import com.mcpscanner.ui.SettingsPanel;
import com.mcpscanner.ui.access.AccessServices;
import com.mcpscanner.ui.access.MiningDialogs;
import com.mcpscanner.ui.access.MiningServices;
import com.mcpscanner.ui.engine.ConfirmedMcpOnlyScan;
import com.mcpscanner.ui.engine.McpOnlyScanMenu;
import com.mcpscanner.ui.identities.ReconnectPrompt;
import com.mcpscanner.ui.scans.MessageEditors;
import com.mcpscanner.ui.scans.ScansServices;
import com.mcpscanner.ui.scans.SwingDelay;
import com.mcpscanner.ui.scans.SwingTargetNavigator;
import com.mcpscanner.ui.sendto.MontoyaSendToDestinations;
import com.mcpscanner.ui.sendto.SendToShortcuts;
import com.mcpscanner.ui.widgets.DaemonReadScheduler;
import com.mcpscanner.ui.widgets.FirstOccurrenceErrors;
import com.mcpscanner.ui.widgets.UiReads;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.Optional;
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
        BurpEdition edition = BurpEdition.of(api);
        ExtensionFoundation foundation = ExtensionFoundation.create(api);
        ConnectionWiring connection = ConnectionWiring.create(api, foundation);
        OAuthWiring oauth = OAuthWiring.create(api, foundation, connection.burpHttp());
        IdentityWiring identities = IdentityWiring.create(foundation, oauth);
        RequestBuildingWiring requests = RequestBuildingWiring.create(foundation, connection, new CurrentAuthHolder());
        connection.resetOnDisconnect(requests.sessionResets());
        Optional<ProfessionalFeatures> professional = ProfessionalFeatures.createIfScanningAvailable(edition, api,
                foundation, connection, oauth, requests, automation);
        connection.resetOnDisconnect(oauth.sessionResets());
        professional.ifPresent(ProfessionalFeatures::resetAccessOnDisconnect);

        ShutdownHooks shutdown = new ShutdownHooks(api.logging()::logToError);
        DaemonReadScheduler uiReads = new DaemonReadScheduler();
        UiReads backgroundReads = UiReads.background(uiReads,
                new FirstOccurrenceErrors(foundation.eventLog()::error, foundation.eventLog()::debug)::report);
        McpScannerTab tab = registerUiOnEdt(api, foundation, connection, requests, oauth, identities,
                backgroundReads, professional);
        shutdown.add("MCP Scanner tab", tab::shutdown);
        shutdown.add("UI reads", uiReads::shutdown);
        professional.ifPresent(pro -> {
            installProfessionalUi(api, foundation, connection, pro, tab, backgroundReads);
            pro.install(shutdown);
        });
        connection.start(shutdown);
        professional.ifPresent(pro -> pro.start(automation, shutdown));
        oauth.addShutdownHooks(shutdown);
        professional.ifPresent(pro -> pro.addDiscoveryShutdownHooks(shutdown));
        identities.addShutdownHooks(shutdown);
        professional.ifPresent(pro -> pro.addFinalShutdownHooks(shutdown));
        shutdown.add("Event log", foundation.eventLog()::shutdown);
        api.extension().registerUnloadingHandler(shutdown);

        logLoaded(api, foundation, edition);
    }

    private static void logLoaded(MontoyaApi api, ExtensionFoundation foundation, BurpEdition edition) {
        foundation.eventLog().info(edition.loadMessage());
        api.logging().logToOutput(ExtensionMetadata.NAME + " loaded successfully");
    }

    private static ScanServices scanServices(MontoyaApi api, ExtensionFoundation foundation,
                                             ProfessionalFeatures pro) {
        ScanningWiring scanning = pro.scanning();
        return new ScanServices(scanning.scanLauncher(), scanning.checkRegistry(), foundation.checkSettings(),
                scanning.generationSettings(), scanning.scanModeSetting(), DestructiveScanPrompt.modal(dialogOwner(api)),
                scanning.scanOwnerArguments(), pro.signedInConsent().setting());
    }

    private static void installProfessionalUi(MontoyaApi api, ExtensionFoundation foundation,
                                              ConnectionWiring connection,
                                              ProfessionalFeatures pro, McpScannerTab tab, UiReads uiReads) {
        AccessServices accessServices = accessServices(foundation, connection, pro.identityDiscovery(), pro.access(),
                pro.scanning()).withMining(miningServices(api, foundation, pro.mining()));
        ScansServices scansServices = scansServices(api, foundation, pro.engine());
        onEdt(api, () -> {
            tab.installAccess(accessServices);
            tab.installScans(scansServices);
        });
        tab.writeReplayApproval().ifPresent(approval -> api.userInterface().registerContextMenuItemsProvider(
                mcpOnlyScanMenu(foundation, pro, uiReads, approval)));
    }

    private static McpOnlyScanMenu mcpOnlyScanMenu(ExtensionFoundation foundation, ProfessionalFeatures pro,
                                                   UiReads uiReads, WriteReplayApproval approval) {
        AccessWiring access = pro.access();
        return new McpOnlyScanMenu(new ConfirmedMcpOnlyScan(access.invokedTools(), uiReads, approval,
                access.confirmations()::confirm, foundation.eventLog(), pro.scanning().engineScans()));
    }

    private static AccessServices accessServices(ExtensionFoundation foundation,
                                                 ConnectionWiring connection, IdentityDiscoveryWiring identities,
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
                                                 ConnectionWiring connection, RequestBuildingWiring requests,
                                                 OAuthWiring oauth, IdentityWiring identities, UiReads uiReads,
                                                 Optional<ProfessionalFeatures> professional) {
        return onEdt(api, () -> registerUi(api, foundation,
                tabDependencies(api, foundation, connection, requests, oauth, identities, uiReads, professional),
                connection));
    }

    private static McpScannerTabDependencies tabDependencies(MontoyaApi api, ExtensionFoundation foundation,
                                                             ConnectionWiring connection,
                                                             RequestBuildingWiring requests, OAuthWiring oauth,
                                                             IdentityWiring identities, UiReads uiReads,
                                                             Optional<ProfessionalFeatures> professional) {
        return new McpScannerTabDependencies(connection.clientManager(), api.logging(), foundation.configStore(),
                foundation.eventLog(), requests.authHolder(), requests.requestRenderer(),
                ServerConfigPanel.create(foundation.configStore(), oauth.authorizationFlow(), oauth.discoverer(),
                        oauth.authorizationGate()::reset, dialogOwner(api)),
                requests.sendToConnections(), oauth.optionalGrants()::create,
                BurpNetworkingPrompt.modal(dialogOwner(api)),
                new IdentityDependencies(foundation.identities(),
                        professional.map(ProfessionalFeatures::identityListings).orElseGet(IdentityListings::new),
                        professional.map(ProfessionalFeatures::comparedDiscovery).orElse(ComparedDiscovery.NONE),
                        foundation.toolCallRefusals(),
                        identities::credentialServices, ReconnectPrompt.modal(dialogOwner(api))),
                uiReads, dialogOwner(api), professional.map(pro -> scanServices(api, foundation, pro)));
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
        SettingsPanel globalSettings = new SettingsPanel(foundation.configStore(), dependencies.settingsScope());
        api.userInterface().registerSettingsPanel(globalSettings.asBurpSettingsPanel());
        return tab;
    }
}
