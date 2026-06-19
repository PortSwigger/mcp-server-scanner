package com.mcpscanner.checks.content;

public record InspectedField(SourceObjectType objectType, String objectName, String fieldPath, String value) {
}
