package com.mcpscanner.ui.identities;

public enum UsersMode {
    PRIMARY_AND_COMPARED("Connect, discovery and Scan", "a scan as %s only reaches"),
    PRIMARY_ONLY("Connect and discovery", "requests as %s only reach");

    private final String primaryRuns;
    private final String anonymousReach;

    UsersMode(String primaryRuns, String anonymousReach) {
        this.primaryRuns = primaryRuns;
        this.anonymousReach = anonymousReach;
    }

    public boolean comparesUsers() {
        return this == PRIMARY_AND_COMPARED;
    }

    public int shownUsers(int registeredUsers) {
        return comparesUsers() ? registeredUsers : 1;
    }

    public String primaryRuns() {
        return primaryRuns;
    }

    String anonymousReach(String user) {
        return anonymousReach.formatted(user);
    }
}
