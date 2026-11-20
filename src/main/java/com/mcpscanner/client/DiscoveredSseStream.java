package com.mcpscanner.client;

import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.InFlightServerPings;
import com.mcpscanner.mcp.RawSseFrame;
import com.mcpscanner.mcp.ServerPings;
import com.mcpscanner.mcp.SseFrame;
import com.mcpscanner.mcp.SseResponseParser;
import com.mcpscanner.core.connection.SseStreamFactory;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequests;
import com.mcpscanner.core.protocol.McpSse;

import java.net.URI;
import java.util.function.Consumer;
import java.util.function.Function;

final class DiscoveredSseStream implements SseStreamFactory.Stream {

    private static final long ADMISSION_REQUEST_ID = 1L;

    private final URI messageUrl;
    private final SseReplyReader reader;
    private final Consumer<String> admissionReplies;
    private final InFlightServerPings inFlightPings;
    private final SseStreamOpening opening;
    private final SseExchangeListener listener;
    private final Function<McpRequests.Request, SseMessagePost> poster;
    private boolean endpointAnnounced;

    DiscoveredSseStream(URI messageUrl, SseReplyReader reader, Consumer<String> admissionReplies,
                        ServerPings serverPings, SseStreamOpening opening, SseExchangeListener listener,
                        Function<McpRequests.Request, SseMessagePost> poster) {
        this.messageUrl = messageUrl;
        this.reader = reader;
        this.admissionReplies = admissionReplies;
        this.opening = opening;
        this.listener = listener;
        this.poster = poster;
        this.inFlightPings = new InFlightServerPings(serverPings, this::postServerRequestReply);
    }

    @Override
    public String nextEvent() {
        if (!endpointAnnounced) {
            endpointAnnounced = true;
            return endpointEvent();
        }
        RawSseFrame frame = nextFrameForCaller();
        if (frame == null) {
            return null;
        }
        listener.eventReceived(opening, frame);
        recordAdmissionReply(frame.text());
        return frame.text();
    }

    @Override
    public McpFlow.HttpResponse post(String endpoint, McpRequests.Request request) {
        inFlightPings.callStarted(request);
        SseMessagePost posted = poster.apply(request);
        listener.messagePosted(opening, request, posted);
        reader.beginReplyWait();
        return posted.response();
    }

    @Override
    public void close() {
        reader.close();
    }

    private RawSseFrame nextFrameForCaller() {
        RawSseFrame frame = reader.nextFrame();
        while (frame != null && answeredServerRequest(frame.text())) {
            frame = reader.nextFrame();
        }
        return frame;
    }

    private void recordAdmissionReply(String frame) {
        if (McpSse.reply(frame, ADMISSION_REQUEST_ID, BoundedBodyReader.MAX_RESPONSE_BYTES) != null) {
            admissionReplies.accept(SseResponseParser.extractJsonRpcResponse(frame));
        }
    }

    private boolean answeredServerRequest(String frame) {
        SseFrame event = SseFrame.parse(frame);
        return event.isMessage() && event.hasData() && inFlightPings.consume(event.data());
    }

    private void postServerRequestReply(McpRequests.Request reply) {
        try {
            poster.apply(reply);
        } catch (IllegalStateException replyNotDelivered) {
        }
    }

    private String endpointEvent() {
        String query = messageUrl.getRawQuery() == null ? "" : "?" + messageUrl.getRawQuery();
        return "event: endpoint\ndata: " + messageUrl.getRawPath() + query + "\n\n";
    }
}
