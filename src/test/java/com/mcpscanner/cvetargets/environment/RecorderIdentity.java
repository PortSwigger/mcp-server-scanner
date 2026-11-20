package com.mcpscanner.cvetargets.environment;

public record RecorderIdentity(String container, String address, String image) {

    public static final RecorderIdentity SHARED = new RecorderIdentity("cvet-interaction-recorder", "10.250.77.250",
            "mcp-cve-target/interaction-recorder:1");

    public String trustVolume() {
        return container + "-trust";
    }
}
