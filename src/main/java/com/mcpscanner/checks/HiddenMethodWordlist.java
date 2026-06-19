package com.mcpscanner.checks;

import java.util.List;

public final class HiddenMethodWordlist {

    public static final List<JsonRpcMethodProbe> PROBES = List.of(
            new JsonRpcMethodProbe("rpc.discover"),
            new JsonRpcMethodProbe("rpc.describe"),
            new JsonRpcMethodProbe("rpc.info"),
            new JsonRpcMethodProbe("rpc.help"),
            new JsonRpcMethodProbe("rpc.methods"),
            new JsonRpcMethodProbe("rpc.list"),
            new JsonRpcMethodProbe("rpc.listMethods"),

            new JsonRpcMethodProbe("system.listMethods"),
            new JsonRpcMethodProbe("system.methodHelp"),
            new JsonRpcMethodProbe("system.methodSignature"),
            new JsonRpcMethodProbe("system.describe"),
            new JsonRpcMethodProbe("system.info"),

            new JsonRpcMethodProbe("admin.nodeInfo"),
            new JsonRpcMethodProbe("admin.peers"),
            new JsonRpcMethodProbe("admin.datadir"),
            new JsonRpcMethodProbe("admin.config"),
            new JsonRpcMethodProbe("admin.info"),
            new JsonRpcMethodProbe("admin.status"),

            new JsonRpcMethodProbe("debug.info"),
            new JsonRpcMethodProbe("debug.log"),
            new JsonRpcMethodProbe("debug.dumpBlock"),
            new JsonRpcMethodProbe("debug.memStats"),
            new JsonRpcMethodProbe("debug.cpuProfile"),
            new JsonRpcMethodProbe("debug.stacks"),
            new JsonRpcMethodProbe("debug.traceTransaction"),

            new JsonRpcMethodProbe("internal.info"),
            new JsonRpcMethodProbe("internal.status"),
            new JsonRpcMethodProbe("internal.config"),
            new JsonRpcMethodProbe("internal.logs"),
            new JsonRpcMethodProbe("internal.metrics"),
            new JsonRpcMethodProbe("internal.health"),
            new JsonRpcMethodProbe("internal.state"),
            new JsonRpcMethodProbe("internal.version"),

            new JsonRpcMethodProbe("dev.info"),
            new JsonRpcMethodProbe("dev.status"),
            new JsonRpcMethodProbe("dev.config"),
            new JsonRpcMethodProbe("dev.logs"),
            new JsonRpcMethodProbe("dev.debug"),
            new JsonRpcMethodProbe("dev.trace"),

            new JsonRpcMethodProbe("$/cancelRequest"),
            new JsonRpcMethodProbe("$/progress"),
            new JsonRpcMethodProbe("$/setTrace"),
            new JsonRpcMethodProbe("$/logTrace"),

            new JsonRpcMethodProbe("debug/info"),
            new JsonRpcMethodProbe("admin/info"),
            new JsonRpcMethodProbe("system/listMethods"),
            new JsonRpcMethodProbe("internal/config"),
            new JsonRpcMethodProbe("dev/debug"),
            new JsonRpcMethodProbe("mcp.tools/list"),
            new JsonRpcMethodProbe("tools.list"),

            new JsonRpcMethodProbe("echo"),
            new JsonRpcMethodProbe("test")
    );

    private HiddenMethodWordlist() {}
}
