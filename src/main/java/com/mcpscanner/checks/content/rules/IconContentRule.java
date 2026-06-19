package com.mcpscanner.checks.content.rules;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.IconRule;
import com.mcpscanner.checks.content.ContentRule;
import com.mcpscanner.checks.content.DiscoveredContent;
import com.mcpscanner.checks.content.InspectedField;
import com.mcpscanner.checks.content.SourceObjectType;
import com.mcpscanner.checks.content.Violation;
import com.mcpscanner.checks.issue.IssueMetadata;
import com.mcpscanner.mcp.IconDescriptor;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpToolDefinition;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class IconContentRule implements ContentRule {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("https", "data");
    private static final String HTTP_SCHEME = "http";
    private static final String DATA_SCHEME = "data";
    private static final String SVG_MIME_TYPE = "image/svg+xml";
    private static final int MAX_DIMENSION = 4096;
    private static final String SVG_EXTENSION = ".svg";
    private static final String SERVER_OBJECT_NAME = "(initialize)";
    private static final String SRC_FIELD = "src";
    private static final String MIME_TYPE_FIELD = "mimeType";
    private static final String SIZES_FIELD = "sizes";

    @Override
    public String id() {
        return "discovery-content-scanner.icon";
    }

    @Override
    public String displayName() {
        return "Unsafe Icon URIs";
    }

    @Override
    public AuditIssueSeverity severity() {
        return AuditIssueSeverity.MEDIUM;
    }

    @Override
    public List<Violation> evaluate(InspectedField field) {
        return List.of();
    }

    @Override
    public List<Violation> evaluateContent(DiscoveredContent content, HttpService host) {
        if (content == null) {
            return List.of();
        }
        String serverHost = host == null ? null : host.host();
        List<Violation> violations = new ArrayList<>();
        if (content.serverInfo() != null) {
            inspectIcons(content.serverInfo().icons(), SourceObjectType.SERVER_INFO,
                    SERVER_OBJECT_NAME, serverHost, violations);
        }
        for (McpToolDefinition tool : content.tools()) {
            inspectIcons(tool.icons(), SourceObjectType.TOOL, tool.name(), serverHost, violations);
        }
        for (McpResourceDefinition resource : content.resources()) {
            inspectIcons(resource.icons(), SourceObjectType.RESOURCE, resource.name(), serverHost, violations);
        }
        for (McpPromptDefinition prompt : content.prompts()) {
            inspectIcons(prompt.icons(), SourceObjectType.PROMPT, prompt.name(), serverHost, violations);
        }
        return violations;
    }

    private void inspectIcons(List<IconDescriptor> icons,
                              SourceObjectType type,
                              String objectName,
                              String serverHost,
                              List<Violation> sink) {
        if (icons == null) {
            return;
        }
        for (int i = 0; i < icons.size(); i++) {
            inspectIcon(icons.get(i), type, objectName, i, serverHost, sink);
        }
    }

    private void inspectIcon(IconDescriptor icon,
                             SourceObjectType type,
                             String objectName,
                             int index,
                             String serverHost,
                             List<Violation> sink) {
        if (icon == null) {
            return;
        }
        inspectSrc(icon.src(), type, objectName, index, serverHost, sink);
        inspectSvg(icon.src(), icon.mimeType(), type, objectName, index, sink);
        inspectSizes(icon.sizes(), type, objectName, index, sink);
    }

    private void inspectSrc(String src, SourceObjectType type, String objectName, int index,
                            String serverHost, List<Violation> sink) {
        URI parsed = parseSafely(src);
        String scheme = schemeOf(parsed);
        if (scheme == null) {
            return;
        }
        if (HTTP_SCHEME.equals(scheme)) {
            sink.add(violation(type, objectName, index, SRC_FIELD, src, IconRule.HTTP_SCHEME));
        } else if (!ALLOWED_SCHEMES.contains(scheme)) {
            sink.add(violation(type, objectName, index, SRC_FIELD, src, IconRule.UNSAFE_SCHEME));
        } else if (!DATA_SCHEME.equals(scheme) && isCrossOrigin(parsed, serverHost)) {
            sink.add(violation(type, objectName, index, SRC_FIELD, src, IconRule.CROSS_ORIGIN));
        }
    }

    private void inspectSvg(String src, String mimeType, SourceObjectType type, String objectName, int index,
                            List<Violation> sink) {
        if (mimeType != null && SVG_MIME_TYPE.equalsIgnoreCase(mimeType)) {
            sink.add(violation(type, objectName, index, MIME_TYPE_FIELD, mimeType, IconRule.SVG_MIME));
        } else if (isSvgSource(src)) {
            sink.add(violation(type, objectName, index, SRC_FIELD, src, IconRule.SVG_MIME));
        }
    }

    private static boolean isSvgSource(String src) {
        if (src == null) {
            return false;
        }
        URI parsed = parseSafely(src);
        String path = parsed == null ? src : parsed.getPath();
        return path != null && path.toLowerCase(Locale.ROOT).endsWith(SVG_EXTENSION);
    }

    private void inspectSizes(List<String> sizes, SourceObjectType type, String objectName, int index,
                              List<Violation> sink) {
        if (sizes == null) {
            return;
        }
        for (String size : sizes) {
            if (isOversized(size)) {
                sink.add(violation(type, objectName, index, SIZES_FIELD, size, IconRule.OVERSIZED));
            }
        }
    }

    private Violation violation(SourceObjectType type, String objectName, int index,
                                String fieldName, String value, IconRule subRule) {
        String fieldPath = "icons[" + index + "]." + fieldName + " (" + subRule.label() + ")";
        InspectedField field = new InspectedField(type, objectName, fieldPath, value);
        return new Violation(this, field, value, subRule.severity());
    }

    private static URI parseSafely(String src) {
        if (src == null || src.isBlank()) {
            return null;
        }
        try {
            return URI.create(src);
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private static String schemeOf(URI parsed) {
        return parsed == null || parsed.getScheme() == null
                ? null
                : parsed.getScheme().toLowerCase(Locale.ROOT);
    }

    private static boolean isCrossOrigin(URI parsed, String serverHost) {
        if (parsed == null || serverHost == null) {
            return false;
        }
        String host = parsed.getHost();
        return host != null && !host.equalsIgnoreCase(serverHost);
    }

    @Override
    public IssueMetadata metadata() {
        return RuleMetadata.ICON.withReferences(List.of(
                "https://modelcontextprotocol.io/specification/2025-11-25/basic/index#icons",
                "https://developer.mozilla.org/en-US/docs/Web/SVG/Element/script"));
    }

    private static boolean isOversized(String size) {
        if (size == null || "any".equalsIgnoreCase(size)) {
            return false;
        }
        for (String token : size.trim().split("\\s+")) {
            String[] parts = token.split("(?i)x");
            if (parts.length != 2) {
                continue;
            }
            try {
                int width = Integer.parseInt(parts[0]);
                int height = Integer.parseInt(parts[1]);
                if (width > MAX_DIMENSION || height > MAX_DIMENSION) {
                    return true;
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return false;
    }
}
