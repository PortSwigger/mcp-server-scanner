package com.mcpscanner.signedin;

import com.mcpscanner.auth.oauth.CallbackListener;
import com.mcpscanner.auth.oauth.CallbackResult;

import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

record CallbackWait(CallbackListener listener, String state, Duration limit) {

    boolean codeArrived() {
        try {
            CallbackResult result = listener.awaitCallback().get(limit.toMillis(), TimeUnit.MILLISECONDS);
            return !result.isError() && result.code() != null && state.equals(result.state());
        } catch (TimeoutException | ExecutionException noCode) {
            return false;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
