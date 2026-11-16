package com.mcpscanner.scan.request;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.scan.ArgumentPath;
import com.mcpscanner.scan.UriTemplateExpansion;

import java.util.Map;
import java.util.Optional;

public interface ScanMessage {

    RequestFamily family();

    String subject();

    Optional<UriTemplateExpansion.Result> templateExpansion();

    default Optional<ArgumentPath> addedArgument() {
        return Optional.empty();
    }

    HttpRequest renderWith(ScanMessageRenderer renderer, String mcpEndpoint, Map<String, String> sessionHeaders);
}
