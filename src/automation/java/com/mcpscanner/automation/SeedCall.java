package com.mcpscanner.automation;

import com.fasterxml.jackson.databind.node.ObjectNode;

public record SeedCall(String method, ObjectNode params) {
}
