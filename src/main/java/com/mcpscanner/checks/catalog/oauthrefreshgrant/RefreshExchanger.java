package com.mcpscanner.checks.catalog.oauthrefreshgrant;

import burp.api.montoya.http.Http;
import com.mcpscanner.auth.grant.RefreshGrant;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;

import java.util.Optional;
import java.util.Set;

final class RefreshExchanger {

    private final Http http;
    private final RefreshRequestFactory requests;
    private final TokenResponseParser parser = new TokenResponseParser();

    RefreshExchanger(Http http, RefreshRequestFactory requests) {
        this.http = http;
        this.requests = requests;
    }

    RefreshExchange exchange(RefreshGrant grant, ClientAuthentication authentication) {
        return exchange(grant, grant.refreshToken(), authentication, Optional.empty());
    }

    RefreshExchange exchange(RefreshGrant grant, String refreshToken, ClientAuthentication authentication,
                             Optional<Set<String>> scope) {
        return parser.parse(authentication,
                OAuthHttp.exchange(http, requests.refresh(grant, refreshToken, authentication, scope)));
    }
}
