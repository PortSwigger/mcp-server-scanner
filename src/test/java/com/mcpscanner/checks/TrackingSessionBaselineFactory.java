package com.mcpscanner.checks;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.scan.ScanStartContext;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

/**
 * Test fixture: a {@link SessionBaselineFactory} that produces header-tracking
 * {@link HttpRequest} mocks so probe code that calls {@code withHeader},
 * {@code withRemovedHeaders}, etc. sees the correct propagated state.
 *
 * <p>Lives in the test source set so production code stays free of test-only
 * tracking infrastructure. The production default uses Burp's real
 * {@link HttpRequest#httpRequestFromUrl(String)} which natively tracks header
 * mutations.
 */
final class TrackingSessionBaselineFactory implements SessionBaselineFactory {

    @Override
    public HttpRequestResponse baselineFor(ScanStartContext context) {
        Map<String, String> seedHeaders = new LinkedHashMap<>(context.headers());
        seedHeaders.putIfAbsent("Content-Type", "application/json");
        seedHeaders.putIfAbsent("Accept", "application/json");
        HttpService service = serviceFromUrl(context.endpoint());
        String path = pathFromUrl(context.endpoint());
        HttpRequest request = trackingRequest(service, path, seedHeaders, SYNTHETIC_BODY);
        return HttpRequestResponse.httpRequestResponse(request, null);
    }

    private static HttpService serviceFromUrl(String url) {
        URI uri = URI.create(url);
        boolean secure = "https".equalsIgnoreCase(uri.getScheme());
        int port = uri.getPort() != -1 ? uri.getPort() : (secure ? 443 : 80);
        HttpService service = mock(HttpService.class);
        lenient().when(service.host()).thenReturn(uri.getHost());
        lenient().when(service.port()).thenReturn(port);
        lenient().when(service.secure()).thenReturn(secure);
        return service;
    }

    private static String pathFromUrl(String url) {
        String path = URI.create(url).getPath();
        return (path == null || path.isEmpty()) ? "/" : path;
    }

    private static HttpRequest trackingRequest(HttpService service, String path,
                                               Map<String, String> headers, String body) {
        Map<String, String> snapshot = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        snapshot.putAll(headers);
        HttpRequest request = mock(HttpRequest.class);
        List<HttpHeader> headerList = headerList(snapshot);
        lenient().when(request.httpService()).thenReturn(service);
        lenient().when(request.method()).thenReturn("POST");
        lenient().when(request.pathWithoutQuery()).thenReturn(path);
        lenient().when(request.bodyToString()).thenReturn(body);
        lenient().when(request.headers()).thenReturn(headerList);
        lenient().when(request.headerValue(anyString())).thenAnswer(inv -> snapshot.get(inv.getArgument(0)));
        lenient().when(request.withMethod(anyString())).thenReturn(request);
        lenient().when(request.withBody(anyString()))
                .thenAnswer(inv -> trackingRequest(service, path, snapshot, inv.getArgument(0)));
        lenient().when(request.withAddedHeader(anyString(), anyString()))
                .thenAnswer(inv -> trackingRequest(service, path, withPut(snapshot, inv.getArgument(0), inv.getArgument(1)), body));
        lenient().when(request.withHeader(anyString(), anyString()))
                .thenAnswer(inv -> trackingRequest(service, path, withReplace(snapshot, inv.getArgument(0), inv.getArgument(1)), body));
        lenient().when(request.withRemovedHeaders(anyList()))
                .thenAnswer(inv -> trackingRequest(service, path, withRemoved(snapshot, inv.getArgument(0)), body));
        return request;
    }

    private static Map<String, String> withPut(Map<String, String> base, String name, String value) {
        Map<String, String> next = new LinkedHashMap<>(base);
        next.put(name, value);
        return next;
    }

    private static Map<String, String> withReplace(Map<String, String> base, String name, String value) {
        Map<String, String> next = new LinkedHashMap<>(base);
        next.keySet().removeIf(existing -> existing.equalsIgnoreCase(name));
        next.put(name, value);
        return next;
    }

    private static Map<String, String> withRemoved(Map<String, String> base, List<HttpHeader> toRemove) {
        Map<String, String> next = new LinkedHashMap<>(base);
        for (HttpHeader h : toRemove) {
            next.keySet().removeIf(existing -> existing.equalsIgnoreCase(h.name()));
        }
        return next;
    }

    private static List<HttpHeader> headerList(Map<String, String> headers) {
        List<HttpHeader> list = new ArrayList<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            HttpHeader h = mock(HttpHeader.class);
            lenient().when(h.name()).thenReturn(entry.getKey());
            lenient().when(h.value()).thenReturn(entry.getValue());
            list.add(h);
        }
        return list;
    }
}
