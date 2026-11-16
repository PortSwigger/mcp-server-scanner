package com.mcpscanner.automation;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.mcp.McpObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;
import java.util.function.Supplier;

public final class AutomationServer implements AutoCloseable {

    static final String SCAN_ALL_PATH = "/scan-all";
    static final String AUDIT_PATH = "/audit";
    public static final String CHECK_ACCESS_PATH = "/check-access";
    static final String SEND_CANARY_PATH = "/send-canary";

    private static final ObjectMapper JSON = McpObjectMapper.INSTANCE;
    private static final String ORIGIN = "Origin";
    private static final String CONTENT_TYPE = "Content-Type";
    private static final String JSON_CONTENT_TYPE = "application/json";

    private final HttpServer server;
    private final ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "mcp-test-automation");
        thread.setDaemon(true);
        return thread;
    });
    private final HeadlessScanAll scanAll;
    private final LaunchedAudit audit;
    private final HeadlessCheckAccess checkAccess;
    private final SendCanary sendCanary;

    public AutomationServer(int port, HeadlessScanAll scanAll, LaunchedAudit audit, HeadlessCheckAccess checkAccess,
                            SendCanary sendCanary) {
        this.scanAll = scanAll;
        this.audit = audit;
        this.checkAccess = checkAccess;
        this.sendCanary = sendCanary;
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
        } catch (IOException bindFailure) {
            throw new UncheckedIOException(bindFailure);
        }
        server.setExecutor(executor);
        server.createContext(SCAN_ALL_PATH, exchange -> unlessFromABrowser(exchange,
                posted -> jsonPost(posted, ScanAllCommand.class, scanAll::launch)));
        server.createContext(SEND_CANARY_PATH, exchange -> unlessFromABrowser(exchange,
                posted -> jsonPost(posted, SendCanaryCommand.class, sendCanary::run)));
        server.createContext(AUDIT_PATH, exchange -> unlessFromABrowser(exchange, this::audit));
        server.createContext(CHECK_ACCESS_PATH, exchange -> unlessFromABrowser(exchange, this::checkAccess));
    }

    public AutomationServer start() {
        server.start();
        return this;
    }

    public int port() {
        return address().getPort();
    }

    InetSocketAddress address() {
        return server.getAddress();
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private static void unlessFromABrowser(HttpExchange exchange, HttpHandler handler) throws IOException {
        if (exchange.getRequestHeaders().containsKey(ORIGIN)) {
            respond(exchange, 403, Map.of("error", "browser requests are refused"));
            return;
        }
        handler.handle(exchange);
    }

    private static <C> void jsonPost(HttpExchange exchange, Class<C> commandType, Function<C, ?> command)
            throws IOException {
        if (!exchange.getRequestMethod().equals("POST")) {
            respond(exchange, 405, Map.of("error", "POST only"));
            return;
        }
        launch(exchange, commandType, command);
    }

    private void checkAccess(HttpExchange exchange) throws IOException {
        switch (exchange.getRequestMethod()) {
            case "POST" -> launch(exchange, CheckAccessCommand.class, checkAccess::launch);
            case "GET" -> report(exchange, checkAccess::status, "no Check access launched");
            default -> respond(exchange, 405, Map.of("error", "POST or GET only"));
        }
    }

    private void audit(HttpExchange exchange) throws IOException {
        report(exchange, audit::snapshot, "no audit launched");
    }

    private static <T> void launch(HttpExchange exchange, Class<T> commandType, Function<T, ?> launcher)
            throws IOException {
        if (!JSON_CONTENT_TYPE.equals(exchange.getRequestHeaders().getFirst(CONTENT_TYPE))) {
            respond(exchange, 415, Map.of("error", CONTENT_TYPE + " must be " + JSON_CONTENT_TYPE));
            return;
        }
        try {
            T command = JSON.readValue(exchange.getRequestBody(), commandType);
            respond(exchange, 200, launcher.apply(command));
        } catch (RuntimeException | IOException failure) {
            respond(exchange, 500, failed(failure));
        }
    }

    private static void report(HttpExchange exchange, Supplier<? extends Optional<?>> current, String absent)
            throws IOException {
        try {
            Optional<?> snapshot = current.get();
            if (snapshot.isPresent()) {
                respond(exchange, 200, snapshot.get());
            } else {
                respond(exchange, 404, Map.of("error", absent));
            }
        } catch (RuntimeException failure) {
            respond(exchange, 500, failed(failure));
        }
    }

    private static Map<String, String> failed(Exception failure) {
        return Map.of("error", failure.getClass().getSimpleName() + ": " + failure.getMessage());
    }

    private static void respond(HttpExchange exchange, int status, Object body) throws IOException {
        try (exchange) {
            byte[] bytes = JSON.writeValueAsBytes(body);
            exchange.getResponseHeaders().set(CONTENT_TYPE, JSON_CONTENT_TYPE);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
        }
    }
}
