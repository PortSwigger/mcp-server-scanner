package com.mcpscanner.identity.discovery;

public interface ComparedDiscovery {

    void discover(String identityId);

    boolean credentialChangedSinceDiscovery(String identityId);
}
