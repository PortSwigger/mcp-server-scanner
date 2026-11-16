package com.mcpscanner.automation;

import com.fasterxml.jackson.annotation.JsonInclude;

public record LaunchedScan(int requests, @JsonInclude(JsonInclude.Include.NON_NULL) String catalogLimit) {

    public LaunchedScan(int requests) {
        this(requests, null);
    }
}
