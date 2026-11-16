package com.mcpscanner.scan;

import java.util.ArrayList;
import java.util.List;

final class ManualEndPoller implements EndPoller {

    private final List<Runnable> polls = new ArrayList<>();
    private boolean shutDown;
    private int requests;

    @Override
    public void pollLater(Runnable poll) {
        requests++;
        if (!shutDown) {
            polls.add(poll);
        }
    }

    @Override
    public void shutdown() {
        shutDown = true;
        polls.clear();
    }

    boolean isShutDown() {
        return shutDown;
    }

    int pollRequests() {
        return requests;
    }

    int pending() {
        return polls.size();
    }

    void runPending() {
        List<Runnable> due = List.copyOf(polls);
        polls.clear();
        due.forEach(Runnable::run);
    }
}
