package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import com.mcpscanner.checks.shared.oauth.ClientCredentials;
import com.mcpscanner.checks.shared.oauth.TokenRevocation;

import java.util.LinkedHashMap;
import java.util.Map;

final class ProbeTokens {

    private final Map<ClientCredentials, TokenLedger> ledgers = new LinkedHashMap<>();

    TokenLedger ledgerFor(ProbeClient client) {
        return ledgers.computeIfAbsent(client.credentials(), credentials -> new TokenLedger());
    }

    void revoke(TokenRevocation revocation) {
        ledgers.forEach((credentials, ledger) -> revocation.revoke(credentials, ledger.issued()));
    }
}
