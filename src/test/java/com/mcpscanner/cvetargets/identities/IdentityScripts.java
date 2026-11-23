package com.mcpscanner.cvetargets.identities;

import com.mcpscanner.cvetargets.environment.CommandRunner;
import com.mcpscanner.cvetargets.environment.Pause;
import com.mcpscanner.cvetargets.environment.ProcessCommandRunner;

import java.time.Clock;

public record IdentityScripts(ProvisionScript provision, ArmSetupScript setup, SignedInSessionScript signedIn) {

    public static IdentityScripts processes() {
        return using(new ProcessCommandRunner(), Pause.sleeping());
    }

    public static IdentityScripts using(CommandRunner commands, Pause pause) {
        ProvisionScript provision = new ProvisionScript(commands, pause, Clock.systemUTC());
        return new IdentityScripts(provision, new ArmSetupScript(commands), new SignedInSessionScript(provision));
    }
}
