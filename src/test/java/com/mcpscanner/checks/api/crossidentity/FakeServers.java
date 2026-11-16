package com.mcpscanner.checks.api.crossidentity;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.argument;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.arguments;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.method;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.principal;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.session;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.tool;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.uri;

public final class FakeServers {

    private FakeServers() {
    }

    public static Function<HttpRequest, FakeReply> objectStore(boolean vulnerable) {
        return authenticated(request -> {
            if (!"a1".equals(argument(request, "id"))) return FakeReply.toolError("note not found");
            if (!vulnerable && !"A".equals(principal(request))) return FakeReply.toolError("note not found");
            return FakeReply.result("A-PRIVATE-a1 body");
        });
    }

    public static Function<HttpRequest, FakeReply> sharedTemplates() {
        return authenticated(request -> Set.of("t1", "t2").contains(argument(request, "template_id"))
                ? FakeReply.result("TEMPLATE-" + argument(request, "template_id") + " body shared by every user")
                : FakeReply.toolError("template not found"));
    }

    public static Function<HttpRequest, FakeReply> flakyForPeer() {
        int[] calls = {0};
        return authenticated(request -> {
            if (!"a1".equals(argument(request, "id"))) return FakeReply.toolError("note not found");
            if ("B".equals(principal(request)) && calls[0]++ > 0) {
                return FakeReply.result("A-PRIVATE-a1 body " + (calls[0] % 2 == 0 ? "" : "(cached)"));
            }
            return FakeReply.result("A-PRIVATE-a1 body");
        });
    }

    public static Function<HttpRequest, FakeReply> selectorIgnoredForPeer() {
        return authenticated(request -> "a1".equals(argument(request, "id")) || "B".equals(principal(request))
                ? FakeReply.result("A-PRIVATE-a1 body") : FakeReply.toolError("note not found"));
    }

    public static Function<HttpRequest, FakeReply> notes() {
        return authenticated(request -> switch (uri(request)) {
            case "notes://team/handbook.md" -> FakeReply.resource("TEAM-HANDBOOK");
            case "notes://alice/private.md" -> FakeReply.resource("ALICE-NOTE");
            default -> FakeReply.rpcError(-32002, "Resource not found");
        });
    }

    public static Function<HttpRequest, FakeReply> refusingPeerInitialize() {
        Function<HttpRequest, FakeReply> sessions = sessions(false);
        return request -> "initialize".equals(method(request)) && "B".equals(principal(request))
                ? FakeReply.unauthorized() : sessions.apply(request);
    }

    public static Function<HttpRequest, FakeReply> peerSeesOwnerMarker() {
        return authenticated(request -> "a1".equals(argument(request, "id"))
                ? FakeReply.result("A".equals(principal(request)) ? "A-PRIVATE-a1 body"
                        : "your notes; shared folder mentions A-PRIVATE-a1")
                : FakeReply.toolError("note not found"));
    }

    public static Function<HttpRequest, FakeReply> anyIdServesTheNote() {
        return authenticated(request -> FakeReply.result("note " + argument(request, "format")));
    }

    public static Function<HttpRequest, FakeReply> whoami() {
        return authenticated(request -> FakeReply.result("notes of " + principal(request)));
    }

    public static Function<HttpRequest, FakeReply> global() {
        return authenticated(request -> tool(request).equals("server_info")
                ? FakeReply.result("server v1") : FakeReply.toolError("unknown tool"));
    }

    public static Function<HttpRequest, FakeReply> adminTool(boolean enforced) {
        return authenticated(request -> {
            if (!tool(request).equals("admin_report")) return FakeReply.toolError("unknown tool");
            if (enforced && !"A".equals(principal(request))) return FakeReply.toolError("insufficient scope");
            return FakeReply.result("ADMIN-EFFECT report");
        });
    }

    public static Function<HttpRequest, FakeReply> versionDependentScope(boolean enforcedEverywhere) {
        return authenticated(request -> {
            if (!tool(request).equals("admin_report")) return FakeReply.toolError("unknown tool");
            String version = request.headerValue("MCP-Protocol-Version");
            boolean legacyHandler = version == null || version.equals("2024-11-05");
            if (!"A".equals(principal(request)) && (enforcedEverywhere || !legacyHandler)) {
                return FakeReply.toolError("insufficient scopes for this tool");
            }
            return FakeReply.result("ADMIN-EFFECT report");
        });
    }

    public static Function<HttpRequest, FakeReply> legacyHandlerOpen() {
        return request -> {
            if (!tool(request).equals("admin_report")) return FakeReply.toolError("unknown tool");
            if ("2024-11-05".equals(request.headerValue("MCP-Protocol-Version"))) {
                return FakeReply.result("ADMIN-EFFECT report");
            }
            String caller = principal(request);
            if (caller == null) return FakeReply.unauthorized();
            return "A".equals(caller) ? FakeReply.result("ADMIN-EFFECT report") : FakeReply.toolError("insufficient scope");
        };
    }

    public static Function<HttpRequest, FakeReply> processWideCache() {
        Map<String, String> sessions = new HashMap<>(Map.of("sess-A", "A"));
        int[] next = {0};
        return handshaking(request -> {
            String issued = "sess-" + next[0]++;
            if (principal(request) != null) sessions.put(issued, principal(request));
            return issued;
        }, request -> {
            String owner = sessions.get(session(request));
            return FakeReply.result("tenant-" + (owner == null ? "b" : owner.toLowerCase()) + "-org");
        });
    }

    public static Function<HttpRequest, FakeReply> statelessCallerSessions() {
        Map<String, String> clients = new HashMap<>(Map.of("chosen-A", "A", "", "B"));
        return handshaking(request -> null, request -> {
            String key = session(request) == null ? "" : session(request);
            String owner = clients.computeIfAbsent(key, ignored -> principal(request));
            return owner == null ? FakeReply.toolError("requires a valid token")
                    : FakeReply.result("tenant-" + owner.toLowerCase() + "-org");
        });
    }

    public static Function<HttpRequest, FakeReply> unauthenticatedSessionEcho() {
        int[] next = {0};
        return handshaking(request -> "sess-" + next[0]++,
                request -> FakeReply.result("session_key=" + session(request)));
    }

    public static Function<HttpRequest, FakeReply> sessions(boolean bound) {
        Map<String, String> owners = new HashMap<>(Map.of("sess-A", "A"));
        int[] next = {0};
        return authenticated(handshaking(request -> register(owners, "sess-" + next[0]++, principal(request)), request -> {
            String owner = owners.get(session(request));
            if (owner == null || bound && !owner.equals(principal(request))) return FakeReply.sessionNotFound();
            return FakeReply.result("A".equals(owner) ? "ALICE-SESSION-RECORD" : "no record");
        }));
    }

    public static Function<HttpRequest, FakeReply> ownerOnlySessions() {
        Map<String, String> owners = new HashMap<>(Map.of("sess-A", "A"));
        int[] next = {0};
        return authenticated(handshaking(request -> register(owners, "sess-" + next[0]++, principal(request)), request -> {
            if (!principal(request).equals(owners.get(session(request)))) return FakeReply.sessionNotFound();
            return "A".equals(principal(request)) ? FakeReply.result("ALICE-SESSION-RECORD")
                    : FakeReply.toolError("forbidden");
        }));
    }

    public static Function<HttpRequest, FakeReply> rebindingSessions(boolean ownerBound) {
        Map<String, String> owners = new HashMap<>(Map.of("sess-A", "A"));
        int[] next = {0};
        return handshakingAuthenticated(request -> register(owners, "sess-" + next[0]++, principal(request)), request -> {
            String sessionId = session(request);
            if (sessionId == null || !owners.containsKey(sessionId)) return FakeReply.unauthorized();
            String caller = principal(request);
            if (caller != null && !caller.equals(owners.get(sessionId))) {
                if (ownerBound) return FakeReply.sessionNotFound();
                owners.put(sessionId, caller);
            }
            return FakeReply.result("record of " + owners.get(sessionId));
        });
    }

    public static Function<HttpRequest, FakeReply> terminatingSessions(boolean asToolError) {
        Map<String, String> owners = new HashMap<>(Map.of("sess-A", "A"));
        int[] next = {0};
        return handshakingAuthenticated(request -> register(owners, "sess-" + next[0]++, principal(request)), request -> {
            String sessionId = session(request);
            if (!owners.containsKey(sessionId)) {
                return asToolError ? FakeReply.toolError("Session terminated") : FakeReply.sessionNotFound();
            }
            String caller = principal(request);
            if (caller != null && !caller.equals(owners.get(sessionId))) {
                owners.remove(sessionId);
                return asToolError ? FakeReply.toolError("Session terminated")
                        : FakeReply.rpcError(-32001, "Session terminated");
            }
            return FakeReply.result("record of " + owners.get(sessionId));
        });
    }

    public static Function<HttpRequest, FakeReply> echo() {
        return authenticated(request -> {
            String sql = argument(request, "sql");
            if (sql == null || !sql.startsWith("select")) return FakeReply.toolError("syntax error");
            return FakeReply.result(sql.replace("'", "").replace("select ", "row "));
        });
    }

    public static Function<HttpRequest, FakeReply> emptyInbox() {
        return authenticated(request -> "inbox".equals(argument(request, "folder"))
                ? FakeReply.result("{\\\"notes\\\": []}") : FakeReply.toolError("folder not found"));
    }

    public static Function<HttpRequest, FakeReply> open() {
        return request -> FakeReply.result("A-PRIVATE-a1 body");
    }

    public static Function<HttpRequest, FakeReply> counter() {
        int[] count = {0};
        return authenticated(request -> FakeReply.result("call " + count[0]++));
    }

    public static Function<HttpRequest, FakeReply> embeddedResourceStore() {
        return authenticated(request -> "a1".equals(argument(request, "id"))
                ? FakeReply.json("{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"content\":[{\"type\":\"resource\","
                        + "\"resource\":{\"uri\":\"doc://a1\",\"text\":\"A private doc\"}}]}}")
                : FakeReply.toolError("not found"));
    }

    public static Function<HttpRequest, FakeReply> vaults(boolean bound) {
        return authenticated(request -> {
            String vault = argument(request, "vault");
            String caller = principal(request);
            String own = "A".equals(caller) ? "main" : "tenantb";
            String target = vault == null ? own : vault;
            if (!target.equals(own) && (bound || !"A".equals(caller))) {
                return FakeReply.toolError("forbidden: vault is not the caller's bound vault");
            }
            if ("main".equals(target)) return FakeReply.result("main note");
            if ("tenantb".equals(target) && "b.md".equals(argument(request, "path"))) return FakeReply.result("TENANT-B note");
            if ("tenantb".equals(target)) return FakeReply.toolError("note not found");
            return FakeReply.toolError("vault not found");
        });
    }

    public static Function<HttpRequest, FakeReply> files(boolean ownerChecked) {
        return authenticated(request -> {
            String caller = principal(request);
            if (uri(request).equals("file://flows/a/report.txt") && "A".equals(caller)) return FakeReply.resource("A-FILE");
            if (uri(request).equals("file://flows/b/report.txt") && ("B".equals(caller) || !ownerChecked)) {
                return FakeReply.resource("B-FILE");
            }
            return FakeReply.rpcError(-32002, "Resource not found");
        });
    }

    public static Function<HttpRequest, FakeReply> attachments(boolean ownerChecked) {
        return authenticated(request -> {
            String path = arguments(request).path("files").path(0).path("path").asText();
            String caller = principal(request);
            if (path.equals("a/report.txt")) {
                return "A".equals(caller) ? FakeReply.result("A-FILE") : FakeReply.toolError("forbidden");
            }
            if (path.equals("b/report.txt")) {
                boolean readable = "B".equals(caller) || !ownerChecked;
                return FakeReply.result(readable ? "B-FILE" : "Attachment is not accessible from this MCP context");
            }
            return FakeReply.result("ENOENT: no such file " + path);
        });
    }

    public static Function<HttpRequest, FakeReply> pathEchoRefusal() {
        return authenticated(request -> {
            String path = argument(request, "path");
            String caller = principal(request);
            if ("alice/notes.md".equals(path)) {
                return "A".equals(caller) ? FakeReply.result("alice notes body") : FakeReply.toolError("forbidden");
            }
            if ("bob/notes.md".equals(path) && "B".equals(caller)) return FakeReply.result("bob notes body");
            if (path != null && path.startsWith("idor")) return FakeReply.toolError("not found");
            return FakeReply.result(path + " is not available in your workspace.");
        });
    }

    private static String register(Map<String, String> owners, String sessionId, String caller) {
        owners.put(sessionId, caller);
        return sessionId;
    }

    private static Function<HttpRequest, FakeReply> handshaking(Function<HttpRequest, String> issue,
                                                                Function<HttpRequest, FakeReply> operation) {
        return request -> switch (method(request)) {
            case "initialize" -> FakeReply.initialized(issue.apply(request));
            case "notifications/initialized" -> FakeReply.accepted();
            default -> operation.apply(request);
        };
    }

    private static Function<HttpRequest, FakeReply> handshakingAuthenticated(Function<HttpRequest, String> issue,
                                                                             Function<HttpRequest, FakeReply> operation) {
        Function<HttpRequest, FakeReply> handshaking = handshaking(issue, operation);
        return request -> "initialize".equals(method(request)) && principal(request) == null
                ? FakeReply.unauthorized() : handshaking.apply(request);
    }

    public static Function<HttpRequest, FakeReply> authenticated(Function<HttpRequest, FakeReply> handler) {
        return request -> principal(request) == null ? FakeReply.unauthorized() : handler.apply(request);
    }
}
