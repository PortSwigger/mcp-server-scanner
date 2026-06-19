package com.mcpscanner.scan;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Expands RFC 6570 Level 1 URI templates (simple {@code {var}} substitution) and records
 * the UTF-8 byte range each variable occupies in the expanded URI.
 *
 * <p>Each placeholder is substituted with its own variable name as the default value so
 * the resulting URI is deterministic and the recorded byte ranges remain stable across runs.
 */
public final class UriTemplateExpansion {

    private UriTemplateExpansion() {}

    public record Variable(String name, int startInclusive, int endExclusive) {}

    public record Result(String expandedUri, List<Variable> variables) {}

    public static Result expand(String template) {
        if (template == null || template.isEmpty()) {
            return new Result("", List.of());
        }
        StringBuilder expanded = new StringBuilder(template.length());
        List<Variable> variables = new ArrayList<>();

        int cursor = 0;
        while (cursor < template.length()) {
            int open = template.indexOf('{', cursor);
            if (open < 0) {
                expanded.append(template, cursor, template.length());
                break;
            }
            int close = template.indexOf('}', open + 1);
            if (close < 0) {
                expanded.append(template, cursor, template.length());
                break;
            }
            expanded.append(template, cursor, open);
            String variableName = template.substring(open + 1, close);
            int byteStart = utf8ByteLength(expanded);
            expanded.append(variableName);
            int byteEnd = utf8ByteLength(expanded);
            variables.add(new Variable(variableName, byteStart, byteEnd));
            cursor = close + 1;
        }

        return new Result(expanded.toString(), List.copyOf(variables));
    }

    private static int utf8ByteLength(CharSequence text) {
        return text.toString().getBytes(StandardCharsets.UTF_8).length;
    }
}
