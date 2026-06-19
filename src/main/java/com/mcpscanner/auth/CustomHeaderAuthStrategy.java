package com.mcpscanner.auth;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class CustomHeaderAuthStrategy implements AuthStrategy {

    private final Map<String, String> headerMap;

    public CustomHeaderAuthStrategy(Map<String, String> headerMap) {
        this.headerMap = new LinkedHashMap<>(headerMap);
    }

    @Override
    public Map<String, String> headers() {
        return Collections.unmodifiableMap(new LinkedHashMap<>(headerMap));
    }
}
