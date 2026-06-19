package com.mcpscanner.checks;

import java.net.URI;

public record OAuthMetadataSsrfFinding(String sourceDocument, String fieldPath, URI url, String classification) {}
