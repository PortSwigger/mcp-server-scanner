package com.mcpscanner.cvetargets.manifest;

import java.util.List;

final class SignedInSessionValidator {

    void check(LoadedTarget target, List<String> violations) {
        SignedInSessionSetup signedInSession = target.manifest().signedInSession();
        if (signedInSession.declared()) {
            TargetScripts.requireInTargetDirectory(target, "signedInSession", signedInSession.provision(), violations);
        }
    }
}
