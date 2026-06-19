package com.mcpscanner.checks.content;

import burp.api.montoya.http.HttpService;
import com.mcpscanner.mcp.ServerMetadata;

import java.util.List;
import java.util.Objects;

public record ContentRuleContext(
        String sourceUrl,
        ContentSourceKind kind,
        DiscoveredContent content,
        HttpService host,
        List<InspectedField> fields) {

    public ContentRuleContext {
        Objects.requireNonNull(kind, "kind must not be null");
        Objects.requireNonNull(content, "content must not be null");
        fields = fields == null ? List.of() : List.copyOf(fields);
    }

    public static ContentRuleContext forDiscoveryBundle(String sourceUrl,
                                                        DiscoveredContent content,
                                                        HttpService host) {
        return new ContentRuleContext(
                sourceUrl,
                ContentSourceKind.DISCOVERY_BUNDLE,
                content,
                host,
                DiscoveryFieldWalker.walk(content));
    }

    public static ContentRuleContext forResponseBody(String sourceUrl,
                                                     List<InspectedField> fields,
                                                     HttpService host) {
        return new ContentRuleContext(
                sourceUrl,
                ContentSourceKind.RESPONSE_BODY,
                new DiscoveredContent(ServerMetadata.empty(), List.of(), List.of(), List.of(), List.of()),
                host,
                fields);
    }
}
