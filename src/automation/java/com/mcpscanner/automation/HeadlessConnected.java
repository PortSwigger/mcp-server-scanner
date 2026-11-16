package com.mcpscanner.automation;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpScannerSession;

record HeadlessConnected(ConnectResult inventory, McpScannerSession session, AuthStrategy strategy) {
}
