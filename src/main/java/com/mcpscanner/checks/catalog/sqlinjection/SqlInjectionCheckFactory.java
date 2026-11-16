package com.mcpscanner.checks.catalog.sqlinjection;

import com.mcpscanner.checks.api.CheckFactory;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.McpCheck;

public final class SqlInjectionCheckFactory implements CheckFactory {

    @Override
    public McpCheck create(CheckServices services) {
        return new SqlInjectionCheck(services.burpNativeFields(), services.eventLog());
    }
}
