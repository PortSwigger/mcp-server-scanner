package com.mcpscanner;

import burp.api.montoya.MontoyaApi;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.ToolCallRefusals;
import com.mcpscanner.logging.McpEventLog;

record ExtensionFoundation(ExtensionConfigStore configStore,
                           ScanCheckSettings checkSettings,
                           McpEventLog eventLog,
                           ClientIdentityProvider identityProvider,
                           IdentityRegistry identities,
                           ToolCallRefusals toolCallRefusals) {

    static ExtensionFoundation create(MontoyaApi api) {
        ExtensionConfigStore configStore = new ExtensionConfigStore(
                api.persistence().extensionData(), api.persistence().preferences(), api.logging());
        McpEventLog eventLog = new McpEventLog(api.logging());
        IdentityRegistry identities = new IdentityRegistry(new IdentityStore(configStore, eventLog));
        return new ExtensionFoundation(configStore, new ScanCheckSettings(configStore), eventLog,
                ClientIdentityProvider.stored(configStore), identities, new ToolCallRefusals(identities));
    }
}
