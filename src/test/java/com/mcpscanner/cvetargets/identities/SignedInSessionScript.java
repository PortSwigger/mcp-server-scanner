package com.mcpscanner.cvetargets.identities;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.ExtensionMetadata;
import com.mcpscanner.cvetargets.manifest.LoadedTarget;

import java.net.URI;
import java.time.Duration;
import java.util.List;

public final class SignedInSessionScript {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final ProvisionScript scripts;

    public SignedInSessionScript(ProvisionScript scripts) {
        this.scripts = scripts;
    }

    ProvisionedSignedInSession run(LoadedTarget target, URI endpoint, Duration timeout) {
        String output = scripts.outputOf(target, target.manifest().signedInSession().provision(),
                List.of(endpoint.toString(), ExtensionMetadata.SOFTWARE_ID), timeout,
                "signed-in session provisioning");
        try {
            return JSON.readValue(OutputLines.last(output), ProvisionedSignedInSession.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("signed-in session provisioning printed no session: "
                    + OutputLines.tail(output), e);
        }
    }
}
