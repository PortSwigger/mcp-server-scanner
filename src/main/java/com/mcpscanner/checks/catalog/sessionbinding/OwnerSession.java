package com.mcpscanner.checks.catalog.sessionbinding;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.IssuedSession;
import com.mcpscanner.checks.api.crossidentity.OpenedSessions;
import com.mcpscanner.checks.api.crossidentity.OperationSeed;
import com.mcpscanner.checks.api.crossidentity.PrincipalRequests;
import com.mcpscanner.checks.api.crossidentity.PrincipalSessions;
import com.mcpscanner.checks.api.crossidentity.ProbeTransport;
import com.mcpscanner.checks.shared.session.SessionHeaders;

final class OwnerSession {

    private OwnerSession() {
    }

    static IssuedSession<OperationSeed> of(OperationSeed seed, Principal owner, PrincipalRequests requests,
                                      ProbeTransport transport, OpenedSessions opened) {
        if (seed.stateful()) {
            return IssuedSession.issued(seed);
        }
        return new PrincipalSessions(seed, transport, opened).issued(requests.as(owner, seed.request()))
                .flatMap(SessionHeaders::carriedBy)
                .map(seed::inSession);
    }
}
