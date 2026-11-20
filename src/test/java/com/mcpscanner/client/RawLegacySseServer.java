package com.mcpscanner.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class RawLegacySseServer implements AutoCloseable {

    static final String STREAM_HEAD = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
            + "Cache-Control: no-cache\r\nX-Stream: one\r\nX-Stream: two\r\n\r\n";
    static final String POST_REPLY = "HTTP/1.1 202 Accepted\r\nContent-Length: 8\r\nSet-Cookie: a=1\r\n"
            + "Set-Cookie: b=2\r\n\r\nAccepted";
    static final String TOOL = "raw_tool";

    private static final byte[] HEAD_END = "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);

    private final ServerSocket server;
    private final ExecutorService connections = Executors.newCachedThreadPool();
    private final List<byte[]> received = new CopyOnWriteArrayList<>();
    private final List<String> toolsListEvents = new CopyOnWriteArrayList<>();
    private volatile OutputStream stream;

    RawLegacySseServer() throws IOException {
        server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        connections.execute(this::acceptLoop);
    }

    String endpoint() {
        return "http://127.0.0.1:" + server.getLocalPort() + "/sse";
    }

    byte[] receivedStartingWith(String requestLine) {
        return received.stream()
                .filter(bytes -> new String(bytes, StandardCharsets.ISO_8859_1).startsWith(requestLine))
                .filter(bytes -> !requestLine.startsWith("POST") || isToolsList(bytes))
                .findFirst().orElseThrow();
    }

    String toolsListEvent() {
        return toolsListEvents.get(0);
    }

    @Override
    public void close() throws IOException {
        server.close();
        connections.shutdownNow();
    }

    private void acceptLoop() {
        while (!server.isClosed()) {
            try {
                Socket socket = server.accept();
                connections.execute(() -> serve(socket));
            } catch (IOException closed) {
                return;
            }
        }
    }

    private void serve(Socket socket) {
        try (socket) {
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            for (byte[] request = readRequest(in); request.length > 0; request = readRequest(in)) {
                received.add(request);
                if (new String(request, StandardCharsets.ISO_8859_1).startsWith("GET ")) {
                    openStream(out);
                    in.readAllBytes();
                    return;
                }
                answer(request, out);
            }
        } catch (IOException closed) {
            return;
        }
    }

    private void openStream(OutputStream out) throws IOException {
        stream = out;
        push(STREAM_HEAD + "event: endpoint\r\ndata: /messages?session=1\r\n\r\n");
    }

    private void answer(byte[] request, OutputStream out) throws IOException {
        out.write(POST_REPLY.getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
        JsonNode message = McpObjectMapper.INSTANCE.readTree(bodyOf(request));
        if (message.has("id") && message.has("method")) {
            push(eventFor(message));
        }
    }

    private String eventFor(JsonNode message) {
        String id = message.get("id").toString();
        String method = message.path("method").asText();
        if (method.equals("tools/list")) {
            String event = ": tools follow\r\nid: 41\r\nevent: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":" + id
                    + ",\r\ndata: \"result\":{\"tools\":[{\"name\":\"" + TOOL
                    + "\",\"inputSchema\":{\"type\":\"object\"}}]}}\r\n\r\n";
            toolsListEvents.add(event);
            return event;
        }
        return "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":" + resultFor(method)
                + "}\r\n\r\n";
    }

    private static String resultFor(String method) {
        return switch (method) {
            case "initialize" -> "{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{\"tools\":{}},"
                    + "\"serverInfo\":{\"name\":\"raw\",\"version\":\"1\"}}";
            case "resources/list" -> "{\"resources\":[]}";
            case "resources/templates/list" -> "{\"resourceTemplates\":[]}";
            case "prompts/list" -> "{\"prompts\":[]}";
            default -> "{}";
        };
    }

    private synchronized void push(String bytes) throws IOException {
        stream.write(bytes.getBytes(StandardCharsets.UTF_8));
        stream.flush();
    }

    private static boolean isToolsList(byte[] request) {
        return bodyOf(request).contains("\"tools/list\"");
    }

    private static String bodyOf(byte[] request) {
        int start = indexOf(request, HEAD_END) + HEAD_END.length;
        return new String(request, start, request.length - start, StandardCharsets.UTF_8);
    }

    private static byte[] readRequest(InputStream in) throws IOException {
        ByteArrayOutputStream read = new ByteArrayOutputStream();
        while (indexOf(read.toByteArray(), HEAD_END) < 0) {
            int next = in.read();
            if (next < 0) {
                return new byte[0];
            }
            read.write(next);
        }
        read.write(in.readNBytes(contentLength(read.toString(StandardCharsets.ISO_8859_1))));
        return read.toByteArray();
    }

    private static int contentLength(String head) {
        return head.lines()
                .filter(line -> line.toLowerCase(Locale.ROOT).startsWith("content-length:"))
                .map(line -> Integer.parseInt(line.substring(line.indexOf(':') + 1).trim()))
                .findFirst().orElse(0);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int start = 0; start + needle.length <= haystack.length; start++) {
            if (java.util.Arrays.equals(haystack, start, start + needle.length, needle, 0, needle.length)) {
                return start;
            }
        }
        return -1;
    }
}
