package com.mcpscanner.mcp;

import java.util.List;

public record IconDescriptor(String src, String mimeType, List<String> sizes) {

    public IconDescriptor {
        sizes = sizes == null ? List.of() : List.copyOf(sizes);
    }
}
