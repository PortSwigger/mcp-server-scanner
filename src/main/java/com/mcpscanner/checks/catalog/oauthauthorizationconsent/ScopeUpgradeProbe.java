package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import com.mcpscanner.checks.api.ScannerClient;
import com.mcpscanner.checks.api.SignedInProbe;
import com.mcpscanner.checks.api.SkipReason;
import com.mcpscanner.checks.shared.oauth.AuthorizationServer;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

final class ScopeUpgradeProbe {

    private static final Set<String> OPENID_CONNECT_SCOPES = Set.of("openid", "profile", "email", "address", "phone");

    private final AuthorizationServer server;
    private final UnattendedAuthorizer authorizer;
    private final ScopeGrantJudge grants;
    private final ProbeSkips skips;
    private final String sessionSource;

    ScopeUpgradeProbe(AuthorizationServer server, UnattendedAuthorizer authorizer, ScopeGrantJudge grants,
                      ProbeSkips skips, String sessionSource) {
        this.server = server;
        this.authorizer = authorizer;
        this.grants = grants;
        this.skips = skips;
        this.sessionSource = sessionSource;
    }

    Optional<ConsentFinding> probe(ScannerClientAtServer scannerAtServer) {
        Optional<ScannerClient> scanner = scannerAtServer.client();
        if (scanner.isEmpty()) {
            return skipped(scannerAtServer.whyUnknown());
        }
        List<String> granted = scanner.get().grantedScopes().stream().sorted().toList();
        if (granted.isEmpty()) {
            return skipped(SkipReason.prerequisiteMissing("the scanner client's granted scopes are unknown"));
        }
        List<String> extra = server.scopesSupported().stream()
                .filter(scope -> !granted.contains(scope) && !OPENID_CONNECT_SCOPES.contains(scope))
                .toList();
        if (extra.isEmpty()) {
            return skipped(SkipReason.notApplicable("the authorization server advertises no scope beyond the granted \""
                    + String.join(" ", granted) + "\" other than OpenID Connect scopes"));
        }
        return upgrade(new ProbeClient(scanner.get().credentials(), scanner.get().redirectUri()), granted, extra);
    }

    private Optional<ConsentFinding> upgrade(ProbeClient own, List<String> granted, List<String> extra) {
        UnattendedAuthorization control = authorizer.authorize(own, Optional.of(String.join(" ", granted)));
        if (control.code().isEmpty()) {
            return skipped(SkipReason.notApplicable("the scanner's own client received no code without a consent "
                    + "page at its granted scope, so the consent is not remembered"));
        }
        List<String> requested = new ArrayList<>(granted);
        requested.addAll(extra);
        UnattendedAuthorization upgrade = authorizer.authorize(own, Optional.of(String.join(" ", requested)));
        if (upgrade.code().isEmpty()) {
            return Optional.empty();
        }
        FindingDraft draft = new FindingDraft(server.authorizationEndpoint())
                .fact(SignedInFacts.scopeControl(own.clientId(), String.join(" ", granted), sessionSource))
                .fact(SignedInFacts.scopeUpgrade(String.join(" ", requested), String.join(" ", extra)))
                .evidence(control.exchanges())
                .evidence(upgrade.exchanges());
        return grants.judge(own, upgrade.code().get(), extra, draft)
                .map(confidence -> draft.as(ConsentShortcut.BROADER_SCOPE, confidence));
    }

    private Optional<ConsentFinding> skipped(SkipReason reason) {
        skips.notRun(SignedInProbe.SCOPE_UPGRADE, reason);
        return Optional.empty();
    }
}
