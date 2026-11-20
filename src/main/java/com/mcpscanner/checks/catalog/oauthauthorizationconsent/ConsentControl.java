package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.checks.shared.oauth.OAuthResponseParameters;

import java.net.URI;
import java.util.Optional;
import java.util.Set;

final class ConsentControl {

    private static final Set<String> CONSENT_ERRORS =
            Set.of("consent_required", "login_required", "interaction_required", "access_denied");

    private ConsentControl() {
    }

    static Optional<String> whyInconclusive(UnattendedAuthorization authorization) {
        if (authorization.callback().isPresent()) {
            boolean consentError = callbackError(authorization.callback().get()).filter(CONSENT_ERRORS::contains)
                    .isPresent();
            return consentError ? Optional.empty() : Optional.of("the callback carried no consent or login error");
        }
        if (authorization.hopLimitReached()) {
            return Optional.of("the authorization redirects exceeded " + UnattendedAuthorizer.MAX_REDIRECTS + " hops");
        }
        if (authorization.exchanges().isEmpty()) {
            return Optional.of("the authorization endpoint did not answer");
        }
        HttpResponse last = authorization.exchanges().get(authorization.exchanges().size() - 1).response();
        return showsPage(last) ? Optional.empty() : Optional.of("the authorization walk ended on HTTP "
                + last.statusCode() + " " + String.valueOf(last.headerValue("Content-Type")));
    }

    private static boolean showsPage(HttpResponse response) {
        String contentType = response.headerValue("Content-Type");
        return response.statusCode() / 100 == 2 && contentType != null && contentType.contains("text/html");
    }

    private static Optional<String> callbackError(URI callback) {
        String raw = callback.getRawFragment() != null ? callback.getRawFragment() : callback.getRawQuery();
        return raw == null ? Optional.empty() : new OAuthResponseParameters(raw).single("error");
    }
}
