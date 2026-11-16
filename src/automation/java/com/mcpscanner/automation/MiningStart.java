package com.mcpscanner.automation;

import com.mcpscanner.access.mining.MiningListener;
import com.mcpscanner.access.mining.MiningRun;
import com.mcpscanner.access.mining.WriteCallApproval;

import java.util.Optional;

@FunctionalInterface
public interface MiningStart {

    Optional<MiningRun> start(MiningListener listener, WriteCallApproval approval);
}
