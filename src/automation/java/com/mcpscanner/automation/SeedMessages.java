package com.mcpscanner.automation;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.scan.request.McpMessage;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.scan.request.ScanMessage;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

final class SeedMessages {

    private static final Map<String, RequestFamily> FAMILIES = Map.of(
            "tools/call", RequestFamily.TOOLS_CALL,
            "tools/list", RequestFamily.TOOLS_LIST,
            "resources/read", RequestFamily.RESOURCES_READ,
            "resources/list", RequestFamily.RESOURCES_LIST,
            "resources/templates/list", RequestFamily.RESOURCE_TEMPLATES_LIST,
            "prompts/get", RequestFamily.PROMPTS_GET,
            "prompts/list", RequestFamily.PROMPTS_LIST);

    GeneratedScan appendTo(GeneratedScan scan, List<SeedCall> seeds) {
        List<ScanMessage> messages = Stream.concat(scan.messages().stream(), seeds.stream().map(SeedMessages::message))
                .toList();
        return new GeneratedScan(messages, scan.invokedTools());
    }

    private static ScanMessage message(SeedCall seed) {
        RequestFamily family = Optional.ofNullable(FAMILIES.get(seed.method()))
                .orElseThrow(() -> new IllegalArgumentException("Unsupported seed method " + seed.method()));
        ObjectNode params = seed.params() == null ? McpObjectMapper.INSTANCE.createObjectNode() : seed.params().deepCopy();
        return McpMessage.call(family, seed.method(), params);
    }
}
