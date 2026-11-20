package com.mcpscanner.proxy;

record StreamedReply(String json, byte[] event) {

    long size() {
        return event.length;
    }
}
