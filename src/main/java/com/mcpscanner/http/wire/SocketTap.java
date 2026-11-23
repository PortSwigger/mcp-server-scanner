package com.mcpscanner.http.wire;

import burp.api.montoya.http.HttpService;
import com.mcpscanner.http.evidence.BodyCapture;
import com.mcpscanner.http.evidence.WireRecord;

import java.io.InputStream;

final class SocketTap {

    private static final int MAX_RECORDED_BYTES = 16 * 1024 * 1024;

    private final WireRequest written;
    private final BodyCapture read;

    SocketTap(WireRequest written, InputStream read) {
        this.written = written;
        this.read = new BodyCapture(read, MAX_RECORDED_BYTES);
    }

    InputStream read() {
        return read;
    }

    WireRecord record() {
        HttpService service = HttpService.httpService(written.host(), written.port(), written.secure());
        return WireRecord.ofSocket(service, written.bytes(), read.captured(), read.truncated());
    }
}
