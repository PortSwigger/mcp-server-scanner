package com.mcpscanner.auth;

import java.util.Collections;
import java.util.Map;

public class NoAuthStrategy implements AuthStrategy {

    @Override
    public Map<String, String> headers() {
        return Collections.emptyMap();
    }
}
