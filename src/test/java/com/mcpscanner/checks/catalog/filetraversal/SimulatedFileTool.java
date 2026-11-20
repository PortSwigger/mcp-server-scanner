package com.mcpscanner.checks.catalog.filetraversal;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.testutil.SpentRateLimitQuota;
import com.mcpscanner.mcp.McpObjectMapper;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class SimulatedFileTool {

    static final String ROOT = "/srv/workspace";
    private static final HttpResponse TOO_MANY_REQUESTS =
            HttpResponse.httpResponse("HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\n\r\nslow down");
    private static final String SPENT_QUOTA = SpentRateLimitQuota.HEADER_LINES;
    static final String PASSWD = TargetFileTest.PASSWD;
    static final String GIT_CONFIG = TargetFileTest.GIT_CONFIG;
    private static final Map<String, String> FILES = Map.of(
            "/etc/passwd", PASSWD,
            ROOT + "/readme.txt", "hello",
            ROOT + "/.git/config", GIT_CONFIG);
    private static final List<String> DIRECTORIES = List.of("/", "/etc", "/srv", ROOT, ROOT + "/.git");

    record Outcome(String text, boolean error) {}

    static final class Denied extends RuntimeException {
        Denied(String message) {
            super(message);
        }
    }

    enum Policy {
        UNRESTRICTED(value -> read(resolve(value))),
        CONTAINED(value -> {
            String resolved = contained(value);
            if (resolved.substring(ROOT.length()).contains("/.")) {
                throw denied(value);
            }
            return read(resolved);
        }),
        DECODE_AFTER_CHECK(value -> {
            String path = value.startsWith("file://") ? value.substring("file://".length()) : value;
            if (path.contains("../") || path.contains("..\\") || path.startsWith("/")) {
                throw denied(value);
            }
            return read(resolve(URLDecoder.decode(value, StandardCharsets.UTF_8)));
        }),
        PREFIX_MATCH(value -> {
            String resolved = resolve(value);
            if (!resolved.startsWith(ROOT)) {
                throw denied(value);
            }
            return read(resolved);
        }),
        CASE_INSENSITIVE_ACL(value -> {
            if (value.startsWith(".git/")) {
                throw new Denied("acl_denied: path is outside the read whitelist");
            }
            return read(contained(value).toLowerCase(Locale.ROOT));
        }),
        CASE_INSENSITIVE_FILESYSTEM(value -> read(contained(value).toLowerCase(Locale.ROOT))),
        ABSOLUTE_PATHS_ONLY(value -> {
            if (value.contains("..")) {
                throw denied(value);
            }
            return read(resolve(value));
        }),
        ALWAYS_PASSWD(value -> PASSWD),
        ANSWERS_ABOUT_THE_TOPIC(value -> value.contains("passwd")
                ? "Each line of the password file looks like:\n```\n" + PASSWD + "```" : "No such standard file."),
        PARSE_ERROR_LEAK(value -> {
            String content = read(resolve(value));
            throw new Denied("Unexpected token, \"" + content.substring(0, Math.min(10, content.length()))
                    + "\"... is not valid JSON");
        }),
        EXTENSION_ALLOWLIST_TRUNCATING_AT_NUL(value -> {
            requireTextExtension(value);
            int nul = value.indexOf("%00");
            return read(resolve(nul < 0 ? value : value.substring(0, nul)));
        }),
        EXTENSION_ALLOWLIST(value -> {
            requireTextExtension(value);
            return read(resolve(value));
        }),
        CASE_SENSITIVE_GIT_DENYLIST(value -> {
            if (value.contains(".git") || value.contains(".Git") || value.contains(".GIT")) {
                throw new Denied("Access denied - repository metadata is not readable");
            }
            return read(contained(value).toLowerCase(Locale.ROOT));
        }),
        CASE_SENSITIVE_GIT_DENYLIST_ON_A_CASE_SENSITIVE_FILESYSTEM(value -> {
            if (value.contains(".git") || value.contains(".Git") || value.contains(".GIT")) {
                throw new Denied("Access denied - repository metadata is not readable");
            }
            return read(contained(value));
        }),
        STRIPS_DOT_DOT_SLASH_AFTER_COLLAPSING_SLASHES(value -> {
            if (value.startsWith("/") || value.startsWith("file:")) {
                throw denied(value);
            }
            return read(resolve(value.replaceAll("/+", "/").replace("../", "")));
        }),
        WINDOWS_STRIPS_DOT_DOT_ONCE(value -> {
            if (WindowsHost.isAbsolute(value)) {
                throw denied(value);
            }
            return WindowsHost.XP.read(value.replace("../", "").replace("..\\", ""));
        }),
        WINDOWS_DOUBLE_DECODING(value -> {
            String lower = value.toLowerCase(Locale.ROOT);
            if (value.contains("../") || value.contains("..\\") || lower.contains("%2e") || lower.contains("%2f")
                    || lower.contains("%5c") || WindowsHost.isAbsolute(value)) {
                throw denied(value);
            }
            return WindowsHost.XP.read(URLDecoder.decode(URLDecoder.decode(value, StandardCharsets.UTF_8),
                    StandardCharsets.UTF_8));
        }),
        WINDOWS_DRIVE_LETTER_FILTER(value -> {
            if (value.contains("..") || value.startsWith("file:") || value.matches("(?i)^[a-z]:.*")) {
                throw denied(value);
            }
            return WindowsHost.XP.read(value);
        }),
        RAW_PREFIX_CHECK_STRICT_RESOLVER(value -> {
            if (!value.startsWith(ROOT + "/")) {
                throw denied(value);
            }
            return read(resolveStrictly(value));
        }),
        WINDOWS_DOT_ENCODING_FILTER(value -> {
            if (value.contains("../") || value.contains("..\\") || value.toLowerCase(Locale.ROOT).contains("%2e")
                    || WindowsHost.isAbsolute(value)) {
                throw denied(value);
            }
            return WindowsHost.XP.read(URLDecoder.decode(value, StandardCharsets.UTF_8));
        }),
        WINDOWS_CONTAINED(value -> WindowsHost.XP.readContained(URLDecoder.decode(value, StandardCharsets.UTF_8))),
        WINDOWS_FILE_URI_READER(value -> {
            if (!value.startsWith("file://")) {
                throw new Denied("Unsupported URI scheme: " + value);
            }
            return WindowsHost.XP.read(value);
        }),
        WINNT_TRAVERSAL_READER(value -> {
            if (WindowsHost.isAbsolute(value)) {
                throw denied(value);
            }
            return WindowsHost.NT.read(value);
        }),
        MASKS_DENIAL_AS_MISSING(value -> {
            try {
                return read(contained(value));
            } catch (Denied denial) {
                throw new Denied("ENOENT: no such file or directory, open '" + value + "'");
            }
        });

        private final Function<String, String> reader;

        Policy(Function<String, String> reader) {
            this.reader = reader;
        }

        Outcome handle(String value) {
            try {
                return new Outcome(reader.apply(value), false);
            } catch (Denied denial) {
                return new Outcome("Error: " + denial.getMessage(), true);
            }
        }
    }

    private final Policy policy;
    private final List<HttpRequest> sent = new ArrayList<>();
    private final List<String> transientlyRejected = new ArrayList<>();
    private List<String> argumentKeys = List.of("path");

    private int answeredBeforeRateLimit = Integer.MAX_VALUE;
    private Predicate<Outcome> spendsTheQuota = outcome -> false;
    private boolean quotaSpent;

    SimulatedFileTool(Policy policy) {
        this.policy = policy;
    }

    SimulatedFileTool rateLimitingAfter(int answered) {
        this.answeredBeforeRateLimit = answered;
        return this;
    }

    SimulatedFileTool spendingTheQuotaOnceAFileLeaks() {
        spendsTheQuota = outcome -> outcome.text().contains(PASSWD);
        return this;
    }

    SimulatedFileTool spendingTheQuotaFromTheFirstReply() {
        spendsTheQuota = outcome -> true;
        return this;
    }

    SimulatedFileTool rejectingOnceWithATransientError(String value) {
        transientlyRejected.add(value);
        return this;
    }

    SimulatedFileTool reading(String... keysUnderArguments) {
        argumentKeys = List.of(keysUnderArguments);
        return this;
    }

    Http http() {
        Http http = mock(Http.class);
        when(http.sendRequest(any(HttpRequest.class))).thenAnswer(invocation -> {
            HttpRequest request = invocation.getArgument(0);
            sent.add(request);
            return HttpRequestResponse.httpRequestResponse(request,
                    sent.size() > answeredBeforeRateLimit ? TOO_MANY_REQUESTS : reply(request));
        });
        return http;
    }

    List<HttpRequest> sent() {
        return sent;
    }

    private HttpResponse reply(HttpRequest request) throws Exception {
        String value = argument(McpObjectMapper.INSTANCE.readTree(request.bodyToString())).asText();
        Outcome outcome = transientlyRejected.remove(value)
                ? new Outcome("Error: rate limit exceeded, retry later", true)
                : policy.handle(value);
        ObjectNode content = JsonNodeFactory.instance.objectNode().put("type", "text").put("text", outcome.text());
        ObjectNode result = JsonNodeFactory.instance.objectNode();
        result.putArray("content").add(content);
        if (outcome.error()) {
            result.put("isError", true);
        }
        ObjectNode envelope = JsonNodeFactory.instance.objectNode().put("jsonrpc", "2.0").put("id", 7);
        envelope.set("result", result);
        quotaSpent = quotaSpent || spendsTheQuota.test(outcome);
        return HttpResponse.httpResponse("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + (quotaSpent ? SPENT_QUOTA : "") + "\r\n" + McpObjectMapper.INSTANCE.writeValueAsString(envelope));
    }

    private JsonNode argument(JsonNode message) {
        JsonNode node = message.path("params").path("arguments");
        for (String key : argumentKeys) {
            node = node.path(key);
        }
        return node;
    }

    private static String resolve(String value) {
        String path = value.startsWith("file://") ? value.substring("file://".length()) : value;
        return Path.of(ROOT).resolve(path).normalize().toString();
    }

    private static String contained(String value) {
        String resolved = resolve(value);
        if (!resolved.startsWith(ROOT + "/")) {
            throw denied(value);
        }
        return resolved;
    }

    private static void requireTextExtension(String value) {
        if (!value.endsWith(".txt")) {
            throw new Denied("Access denied - only .txt files may be read: " + value);
        }
    }

    private static String resolveStrictly(String value) {
        Deque<String> segments = new ArrayDeque<>();
        for (String segment : value.split("/")) {
            if (segment.equals("..")) {
                if (segments.pollLast() == null) {
                    throw new Denied("Invalid path: " + value + " climbs above the filesystem root");
                }
            } else if (!segment.isEmpty() && !segment.equals(".")) {
                segments.addLast(segment);
            }
        }
        return "/" + String.join("/", segments);
    }

    private record WindowsHost(String systemDirectory) {

        static final WindowsHost XP = new WindowsHost("/windows");
        static final WindowsHost NT = new WindowsHost("/winnt");
        private static final Pattern DRIVE = Pattern.compile("(?i)^/?[a-z]:");

        static boolean isAbsolute(String value) {
            return value.startsWith("/") || value.startsWith("\\") || value.startsWith("file:")
                    || DRIVE.matcher(value).find();
        }

        String read(String value) {
            return readPath(resolve(value));
        }

        String readContained(String value) {
            String resolved = resolve(value);
            if (!resolved.startsWith(ROOT + "/")) {
                throw denied(value);
            }
            return readPath(resolved);
        }

        private String readPath(String path) {
            if (path.equals(systemDirectory + "/win.ini")) {
                return TargetFileTest.WIN_INI;
            }
            String parent = path.substring(0, Math.max(1, path.lastIndexOf('/')));
            if (!List.of("/", "/srv", ROOT, systemDirectory).contains(parent)) {
                throw new Denied("The system cannot find the path specified: " + path);
            }
            throw new Denied("The system cannot find the file specified: " + path);
        }

        private static String resolve(String value) {
            if (value.indexOf('\0') >= 0) {
                throw new Denied("The filename, directory name, or volume label syntax is incorrect");
            }
            String path = value.startsWith("file://") ? value.substring("file://".length()) : value;
            path = DRIVE.matcher(path.replace('\\', '/')).replaceFirst("");
            return Path.of(ROOT).resolve(path).normalize().toString().toLowerCase(Locale.ROOT);
        }
    }

    private static Denied denied(String value) {
        return new Denied("Access denied - path outside allowed directories: " + value + " not in " + ROOT);
    }

    private static String read(String path) {
        String parent = path.contains("/") ? path.substring(0, Math.max(1, path.lastIndexOf('/'))) : "/";
        if (!DIRECTORIES.contains(parent)) {
            throw new Denied("Parent directory does not exist: " + parent);
        }
        String content = FILES.get(path);
        if (content == null) {
            throw new Denied("ENOENT: no such file or directory, open '" + path + "'");
        }
        return content;
    }
}
