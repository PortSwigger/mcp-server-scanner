package com.mcpscanner.checks;

public record IconViolation(String sourceField, IconRule rule, String fieldName, String fieldValue) {
}
