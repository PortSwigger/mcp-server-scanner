package com.mcpscanner.checks.catalog.ssrffilterbypass;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;

public final class SsrfFilterBypassCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        return new SsrfFilterBypassCheck(services.eventLog(), services.collaboratorWatch(), services.lateIssues(),
                services.burpNativeFields());
    }
}
