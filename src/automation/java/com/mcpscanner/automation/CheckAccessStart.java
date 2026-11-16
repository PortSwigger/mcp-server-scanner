package com.mcpscanner.automation;

import com.mcpscanner.access.AccessRow;
import com.mcpscanner.access.AccessRun;
import com.mcpscanner.access.AccessRunListener;

import java.util.List;
import java.util.Optional;

@FunctionalInterface
public interface CheckAccessStart {

    Optional<AccessRun> start(List<AccessRow> rows, AccessRunListener listener);
}
