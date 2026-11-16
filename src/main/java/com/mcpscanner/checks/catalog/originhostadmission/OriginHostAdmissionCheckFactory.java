package com.mcpscanner.checks.catalog.originhostadmission;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;
import com.mcpscanner.checks.shared.session.ProbeSessions;
import com.mcpscanner.checks.shared.stream.FreshSessionStreams;
import com.mcpscanner.checks.shared.stream.JdkStreamOpener;

public final class OriginHostAdmissionCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        ProbeSessions probeSessions = new ProbeSessions(services.authStrategy());
        JdkStreamOpener streamOpener = new JdkStreamOpener(services.eventLog());
        return new OriginHostAdmissionCheck(services.eventLog(), new CredentialHeaders(services.authStrategy()),
                services.probeService(), new FreshSessionStreams(probeSessions, streamOpener), probeSessions,
                services.sseProbeStreams(), streamOpener);
    }
}
