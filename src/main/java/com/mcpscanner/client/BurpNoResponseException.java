package com.mcpscanner.client;

import java.io.IOException;

final class BurpNoResponseException extends IOException {

    BurpNoResponseException(String message) {
        super(message);
    }
}
