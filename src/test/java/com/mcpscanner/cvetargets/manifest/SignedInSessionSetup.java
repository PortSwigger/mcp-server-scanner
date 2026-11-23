package com.mcpscanner.cvetargets.manifest;

import com.fasterxml.jackson.annotation.JsonProperty;

public record SignedInSessionSetup(@JsonProperty(required = true) String provision) {

    public static SignedInSessionSetup none() {
        return new SignedInSessionSetup(null);
    }

    public boolean declared() {
        return provision != null;
    }
}
