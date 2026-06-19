package com.mcpscanner;

public final class ExtensionMetadata {

    public static final String NAME = "MCP Server Scanner";
    public static final String SCANNER_CLIENT_NAME = NAME + "-scanner";
    public static final String VERSION = resolveVersion();

    private static final String FALLBACK_VERSION = "0.1.0";

    private ExtensionMetadata() {
    }

    private static String resolveVersion() {
        String packaged = ExtensionMetadata.class.getPackage().getImplementationVersion();
        return (packaged != null && !packaged.isBlank()) ? packaged : FALLBACK_VERSION;
    }
}
