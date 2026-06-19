package com.mcpscanner.client;

import com.mcpscanner.auth.AuthStrategy;

public record McpServerConfig(String endpoint, TransportType transport, AuthStrategy auth) {}
