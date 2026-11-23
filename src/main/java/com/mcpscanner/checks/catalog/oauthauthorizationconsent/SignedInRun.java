package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.api.OAuthSkipLog;
import com.mcpscanner.checks.shared.oauth.OAuthHttp;

record SignedInRun(HttpRequestResponse hostBase, Http http, OAuthHttp oauthHttp, OAuthSkipLog skips,
                   String subject) {

    String mcpEndpoint() {
        return hostBase.request().url();
    }
}
