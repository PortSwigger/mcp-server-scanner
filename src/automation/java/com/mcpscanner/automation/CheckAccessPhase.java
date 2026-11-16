package com.mcpscanner.automation;

import com.fasterxml.jackson.annotation.JsonProperty;

public enum CheckAccessPhase {
    @JsonProperty("discovering") DISCOVERING(false),
    @JsonProperty("mining") MINING(false),
    @JsonProperty("running") RUNNING(false),
    @JsonProperty("finished") FINISHED(true),
    @JsonProperty("cancelled") CANCELLED(true),
    @JsonProperty("stopped") STOPPED(true),
    @JsonProperty("failed") FAILED(true);

    private final boolean ended;

    CheckAccessPhase(boolean ended) {
        this.ended = ended;
    }

    public boolean ended() {
        return ended;
    }
}
