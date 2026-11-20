package com.mcpscanner.identity.discovery;

public interface ComparedDiscovery {

    ComparedDiscovery NONE = new ComparedDiscovery() {
        @Override
        public void discover(String identityId) {
        }

        @Override
        public boolean credentialChangedSinceDiscovery(String identityId) {
            return false;
        }
    };

    void discover(String identityId);

    boolean credentialChangedSinceDiscovery(String identityId);
}
