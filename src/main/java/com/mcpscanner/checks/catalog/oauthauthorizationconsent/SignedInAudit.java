package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import com.mcpscanner.checks.api.RegisteredClientName;
import com.mcpscanner.checks.api.ScannerClient;
import com.mcpscanner.checks.api.SignedInProbe;
import com.mcpscanner.checks.api.SkipReason;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;

final class SignedInAudit {

    private static final List<SignedInProbe> KEYED = List.of(SignedInProbe.SAME_NAME,
            SignedInProbe.SAME_REDIRECT_HOST, SignedInProbe.SAME_CLIENT_ID_PREFIX);

    private final SignedInProbeClients clients;
    private final ShortcutProbe shortcut;
    private final ScopeUpgradeProbe scopeUpgrade;
    private final ProbeSkips skips;
    private final ScannerClientAtServer scannerAtServer;
    private final Optional<ScannerClient> scanner;

    SignedInAudit(SignedInProbeClients clients, ShortcutProbe shortcut, ScopeUpgradeProbe scopeUpgrade,
                  ProbeSkips skips, ScannerClientAtServer scannerAtServer) {
        this.clients = clients;
        this.shortcut = shortcut;
        this.scopeUpgrade = scopeUpgrade;
        this.skips = skips;
        this.scannerAtServer = scannerAtServer;
        this.scanner = scannerAtServer.client();
    }

    List<ConsentFinding> run() {
        Optional<RegisteredProbe> fresh = clients.fresh();
        if (fresh.isEmpty()) {
            Stream.of(SignedInProbe.values()).filter(probe -> probe != SignedInProbe.SCOPE_UPGRADE)
                    .forEach(probe -> skips.notRun(probe, SignedInSkips.NO_CLIENT_ISSUED));
            return scopeUpgrade.probe(scannerAtServer).stream().toList();
        }
        ShortcutOutcome anyClient = shortcut.probe(SignedInProbe.FRESH_NAME, fresh.get());
        if (anyClient.finding().isPresent()) {
            Stream.of(SignedInProbe.values()).filter(probe -> probe != SignedInProbe.FRESH_NAME)
                    .forEach(probe -> skips.notRun(probe, SignedInSkips.SUBSUMED));
            return List.of(anyClient.finding().get());
        }
        List<ConsentFinding> findings = new ArrayList<>(keyedProbes(fresh.get(), anyClient.authorization()));
        scopeUpgrade.probe(scannerAtServer).ifPresent(findings::add);
        return findings;
    }

    private List<ConsentFinding> keyedProbes(RegisteredProbe fresh, UnattendedAuthorization control) {
        Optional<String> inconclusive = ConsentControl.whyInconclusive(control);
        if (inconclusive.isPresent()) {
            SkipReason reason = SignedInSkips.inconclusiveControl(inconclusive.get());
            return skippedKeyed(reason);
        }
        if (scannerAtServer.foreignIssuer().isPresent()) {
            return skippedKeyed(scannerAtServer.foreignIssuer().get());
        }
        List<ConsentFinding> findings = new ArrayList<>();
        sameName().ifPresent(findings::add);
        sameRedirectHost().ifPresent(findings::add);
        sameClientIdPrefix(fresh).ifPresent(findings::add);
        return findings;
    }

    private List<ConsentFinding> skippedKeyed(SkipReason reason) {
        KEYED.forEach(probe -> skips.notRun(probe, reason));
        return List.of();
    }

    private Optional<ConsentFinding> sameName() {
        if (scanner.isEmpty()) {
            return skipped(SignedInProbe.SAME_NAME, scannerAtServer.whyUnknown());
        }
        Optional<String> name = scanner.get().clientName().value();
        if (name.isEmpty()) {
            return skipped(SignedInProbe.SAME_NAME, SkipReason.prerequisiteMissing(RegisteredClientName.UNKNOWN));
        }
        return registeredThenProbed(SignedInProbe.SAME_NAME, () -> clients.named(name.get()));
    }

    private Optional<ConsentFinding> sameRedirectHost() {
        if (scanner.isEmpty()) {
            return skipped(SignedInProbe.SAME_REDIRECT_HOST, scannerAtServer.whyUnknown());
        }
        return registeredThenProbed(SignedInProbe.SAME_REDIRECT_HOST,
                () -> clients.onHostOf(scanner.get().redirectUri()));
    }

    private Optional<ConsentFinding> sameClientIdPrefix(RegisteredProbe fresh) {
        if (scanner.isEmpty()) {
            return skipped(SignedInProbe.SAME_CLIENT_ID_PREFIX, scannerAtServer.whyUnknown());
        }
        Optional<ClientIdPrefix> prefix = ClientIdPrefix.of(scanner.get().clientId());
        if (prefix.isEmpty()) {
            return skipped(SignedInProbe.SAME_CLIENT_ID_PREFIX, SkipReason.notApplicable("the scanner's client_id "
                    + scanner.get().clientId() + " has no structured prefix"));
        }
        if (prefix.get().sharedBy(fresh.client().clientId())) {
            return skipped(SignedInProbe.SAME_CLIENT_ID_PREFIX, SkipReason.notApplicable("every new client_id starts "
                    + "with " + prefix.get() + ", which the fresh client probe already covers"));
        }
        return prefixedClient(prefix.get()).flatMap(client -> shortcut.probe(SignedInProbe.SAME_CLIENT_ID_PREFIX,
                client).finding());
    }

    private Optional<RegisteredProbe> prefixedClient(ClientIdPrefix prefix) {
        Optional<String> softwareId = scanner.flatMap(ScannerClient::softwareId);
        Optional<RegisteredProbe> client = clients.carrying(softwareId);
        if (client.isEmpty()) {
            skips.notRun(SignedInProbe.SAME_CLIENT_ID_PREFIX, SignedInSkips.NO_CLIENT_ISSUED);
            return Optional.empty();
        }
        if (!prefix.sharedBy(client.get().client().clientId())) {
            skips.notRun(SignedInProbe.SAME_CLIENT_ID_PREFIX, SkipReason.notApplicable("the authorization server "
                    + "issued client_id " + client.get().client().clientId() + " without the scanner's prefix "
                    + prefix + softwareId.map(id -> ", even for software_id " + id).orElse("")));
            return Optional.empty();
        }
        return client;
    }

    private Optional<ConsentFinding> registeredThenProbed(SignedInProbe probe,
                                                          Supplier<Optional<RegisteredProbe>> registration) {
        Optional<RegisteredProbe> client = registration.get();
        if (client.isEmpty()) {
            return skipped(probe, SignedInSkips.NO_CLIENT_ISSUED);
        }
        return shortcut.probe(probe, client.get()).finding();
    }

    private Optional<ConsentFinding> skipped(SignedInProbe probe, SkipReason reason) {
        skips.notRun(probe, reason);
        return Optional.empty();
    }
}
