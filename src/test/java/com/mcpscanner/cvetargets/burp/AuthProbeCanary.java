package com.mcpscanner.cvetargets.burp;

import com.mcpscanner.automation.AuthProbeCommand;
import com.mcpscanner.automation.AuthProbeReport;

interface AuthProbeCanary {

    AuthProbeReport authProbe(AuthProbeCommand command);
}
