package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import com.mcpscanner.engine.McpScanEngine;
import com.mcpscanner.identity.discovery.ComparedDiscovery;
import com.mcpscanner.identity.discovery.IdentityListings;

import java.util.Optional;

final class ProfessionalFeatures {

    private final MontoyaApi api;
    private final ExtensionFoundation foundation;
    private final ConnectionWiring connection;
    private final IdentityDiscoveryWiring identityDiscovery;
    private final ScanFoundation scan;
    private final AccessWiring access;
    private final ScanningWiring scanning;
    private final MiningWiring mining;
    private final RegistrationCleanupWiring registrationCleanup;
    private final SignedInConsentWiring signedInConsent;

    private ProfessionalFeatures(MontoyaApi api, ExtensionFoundation foundation, ConnectionWiring connection,
                                 IdentityDiscoveryWiring identityDiscovery, ScanFoundation scan, AccessWiring access,
                                 ScanningWiring scanning, MiningWiring mining,
                                 RegistrationCleanupWiring registrationCleanup,
                                 SignedInConsentWiring signedInConsent) {
        this.api = api;
        this.foundation = foundation;
        this.connection = connection;
        this.identityDiscovery = identityDiscovery;
        this.scan = scan;
        this.access = access;
        this.scanning = scanning;
        this.mining = mining;
        this.registrationCleanup = registrationCleanup;
        this.signedInConsent = signedInConsent;
    }

    static Optional<ProfessionalFeatures> createIfScanningAvailable(BurpEdition edition, MontoyaApi api,
                                                                    ExtensionFoundation foundation,
                                                                    ConnectionWiring connection,
                                                                    OAuthWiring oauth,
                                                                    RequestBuildingWiring requests,
                                                                    ExtensionAutomation automation) {
        return edition.scanningAvailable()
                ? Optional.of(create(api, foundation, connection, oauth, requests, automation))
                : Optional.empty();
    }

    private static ProfessionalFeatures create(MontoyaApi api, ExtensionFoundation foundation,
                                               ConnectionWiring connection, OAuthWiring oauth,
                                               RequestBuildingWiring requests, ExtensionAutomation automation) {
        SignedInConsentWiring signedInConsent = SignedInConsentWiring.create(api, foundation, connection, oauth);
        IdentityDiscoveryWiring identityDiscovery = IdentityDiscoveryWiring.create(foundation, connection,
                requests.authHolder());
        AccessWiring access = AccessWiring.create(foundation, connection, identityDiscovery.listings(),
                identityDiscovery.discovery(), requests.authHolder(), identityDiscovery.synthetic(),
                identityDiscovery.discovery()::toolsListExchanges);
        ScanFoundation scan = ScanFoundation.create(api, foundation, connection);
        ScanningWiring scanning = ScanningWiring.create(api, foundation, connection, requests, access, scan,
                automation.instrumentation(), automation.launchRenderer(), signedInConsent.consent());
        MiningWiring mining = MiningWiring.create(foundation, connection, access, scanning);
        RegistrationCleanupWiring registrationCleanup = RegistrationCleanupWiring.register(api,
                connection.burpHttp(), foundation.eventLog());
        connection.resetOnDisconnect(scanning.sessionResets());
        return new ProfessionalFeatures(api, foundation, connection, identityDiscovery, scan, access, scanning,
                mining, registrationCleanup, signedInConsent);
    }

    void resetAccessOnDisconnect() {
        connection.resetOnDisconnect(access.sessionResets());
        connection.resetOnDisconnect(mining.sessionResets());
    }

    IdentityDiscoveryWiring identityDiscovery() {
        return identityDiscovery;
    }

    IdentityListings identityListings() {
        return identityDiscovery.listings();
    }

    ComparedDiscovery comparedDiscovery() {
        return identityDiscovery.discovery();
    }

    ScanningWiring scanning() {
        return scanning;
    }

    AccessWiring access() {
        return access;
    }

    MiningWiring mining() {
        return mining;
    }

    SignedInConsentWiring signedInConsent() {
        return signedInConsent;
    }

    McpScanEngine engine() {
        return scan.engine();
    }

    void install(ShutdownHooks shutdown) {
        EngineWiring.registerChecks(scan.engine(), scanning.checkRegistry(), shutdown);
        access.addShutdownHooks(shutdown);
        mining.addShutdownHooks(shutdown);
        signedInConsent.addShutdownHooks(shutdown);
    }

    void start(ExtensionAutomation automation, ShutdownHooks shutdown) {
        scanning.addShutdownHooks(shutdown);
        automation.startIfSwitchedOn(api, foundation, connection, scanning, access, mining,
                signedInConsent, shutdown);
    }

    void addDiscoveryShutdownHooks(ShutdownHooks shutdown) {
        identityDiscovery.addShutdownHooks(shutdown);
    }

    void addFinalShutdownHooks(ShutdownHooks shutdown) {
        registrationCleanup.addShutdownHooks(shutdown);
        scan.addShutdownHooks(shutdown);
    }
}
