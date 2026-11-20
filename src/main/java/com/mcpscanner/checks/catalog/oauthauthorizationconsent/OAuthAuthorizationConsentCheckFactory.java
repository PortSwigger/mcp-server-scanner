package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;

public final class OAuthAuthorizationConsentCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        return new OAuthAuthorizationConsentCheck(services.eventLog(), services.authStrategy(),
                services.signedInConsent());
    }
}
