package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import com.mcpscanner.checks.shared.oauth.Registration;
import com.mcpscanner.checks.shared.oauth.RegistrationStatus;

import java.util.List;
import java.util.Optional;

final class ScriptSchemeRegistrationProbe implements RedirectProbe {

    private static final List<List<String>> SCHEME_SPELLINGS = List.of(
            List.of("javascript:void(0)", "JavaScript:void(0)"),
            List.of("data:text/html,scancheck", "Data:text/html,scancheck"));

    @Override
    public List<RedirectFinding> run(ProbeContext context) {
        if (context.clients().https().isEmpty()) {
            return List.of();
        }
        return SCHEME_SPELLINGS.stream()
                .map(spellings -> firstAccepted(context, spellings))
                .flatMap(Optional::stream)
                .toList();
    }

    private static Optional<RedirectFinding> firstAccepted(ProbeContext context, List<String> spellings) {
        for (String redirectUri : spellings) {
            Registration registration = context.registrar()
                    .register(ProbeClientMetadata.redirectingTo(List.of(redirectUri)));
            if (registration.clientListingAll(List.of(redirectUri)).isPresent()) {
                return Optional.of(finding(context, redirectUri, registration));
            }
            if (registration.status() != RegistrationStatus.REJECTED) {
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    private static RedirectFinding finding(ProbeContext context, String redirectUri, Registration registration) {
        return new RedirectFinding(FindingKind.SCRIPT_SCHEME_REGISTRATION, context.registrar().endpoint(),
                "registered and echoed " + redirectUri, registration.exchange().stream().toList());
    }
}
