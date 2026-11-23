package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import java.util.List;

final class AnyHostRegistrationProbe implements RedirectProbe {

    @Override
    public List<RedirectFinding> run(ProbeContext context) {
        return context.clients().https().stream()
                .map(client -> finding(context, client))
                .toList();
    }

    private static RedirectFinding finding(ProbeContext context, OwnedClient client) {
        return new RedirectFinding(FindingKind.ANY_HOST_REGISTRATION, context.registrar().endpoint(),
                "registered and echoed " + client.callback(),
                List.of(client.registration().evidence()));
    }
}
