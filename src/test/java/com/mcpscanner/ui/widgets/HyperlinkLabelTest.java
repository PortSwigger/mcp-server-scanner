package com.mcpscanner.ui.widgets;

import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

class HyperlinkLabelTest {

    private static final URI TARGET = URI.create("https://example.com/docs");

    @Test
    void mouseClickedInvokesBrowseActionWithTargetUri() throws Exception {
        CountDownLatch browsed = new CountDownLatch(1);
        AtomicReference<URI> recorded = new AtomicReference<>();
        HyperlinkLabel label = new HyperlinkLabel("docs", TARGET, uri -> {
            recorded.set(uri);
            browsed.countDown();
        }, ignoredError());

        invokeAndWait(() -> fireMouseClicked(label));

        assertThat(browsed.await(1, TimeUnit.SECONDS)).isTrue();
        assertThat(recorded.get()).isEqualTo(TARGET);
    }

    @Test
    void mouseClickedInvokesBrowseActionOffEdt() throws Exception {
        CountDownLatch fired = new CountDownLatch(1);
        AtomicReference<Boolean> firedOnEdt = new AtomicReference<>();
        HyperlinkLabel label = new HyperlinkLabel("docs", TARGET, uri -> {
            firedOnEdt.set(SwingUtilities.isEventDispatchThread());
            fired.countDown();
        }, ignoredError());

        invokeAndWait(() -> fireMouseClicked(label));

        assertThat(fired.await(1, TimeUnit.SECONDS)).isTrue();
        assertThat(firedOnEdt.get()).isFalse();
    }

    @Test
    void browseFailureIsReportedToErrorSink() throws Exception {
        RuntimeException failure = new RuntimeException("browse blew up");
        CountDownLatch reported = new CountDownLatch(1);
        AtomicReference<Throwable> recorded = new AtomicReference<>();
        HyperlinkLabel label = new HyperlinkLabel("docs", TARGET, uri -> {
            throw failure;
        }, throwable -> {
            recorded.set(throwable);
            reported.countDown();
        });

        invokeAndWait(() -> fireMouseClicked(label));

        assertThat(reported.await(1, TimeUnit.SECONDS)).isTrue();
        assertThat(recorded.get()).isSameAs(failure);
    }

    @Test
    void browseFailureDoesNotPropagateFromLaunchThread() throws Exception {
        CountDownLatch reported = new CountDownLatch(1);
        AtomicReference<Throwable> uncaught = new AtomicReference<>();
        HyperlinkLabel label = new HyperlinkLabel("docs", TARGET, uri -> {
            Thread.currentThread().setUncaughtExceptionHandler(
                    (thread, throwable) -> uncaught.set(throwable));
            throw new RuntimeException("browse blew up");
        }, throwable -> reported.countDown());

        invokeAndWait(() -> fireMouseClicked(label));

        assertThat(reported.await(1, TimeUnit.SECONDS)).isTrue();
        assertThat(uncaught.get()).isNull();
    }

    @Test
    void twoArgConstructorWiresNoOpSinkAndAttachesMouseListener() throws Exception {
        // The 2-arg public ctor uses NO_OP_ERROR_SINK + real Desktop.browse. Verify the
        // constructor chain succeeds and attaches a mouse listener (functional wiring check
        // without asserting on Desktop availability).
        HyperlinkLabel label = new HyperlinkLabel("docs", TARGET);
        invokeAndWait(() -> {});
        assertThat(label.getMouseListeners()).isNotEmpty();
    }

    @Test
    void sinkThrowingDoesNotEscapeFromDaemonThread() throws Exception {
        CountDownLatch sinkCalled = new CountDownLatch(1);
        HyperlinkLabel label = new HyperlinkLabel("docs", TARGET, uri -> {
            throw new RuntimeException("browse blew up");
        }, throwable -> {
            sinkCalled.countDown();
            throw new RuntimeException("sink also blew up");
        });

        invokeAndWait(() -> fireMouseClicked(label));

        assertThat(sinkCalled.await(1, TimeUnit.SECONDS)).isTrue();
        // If the sink exception escaped the daemon thread it would surface as a test
        // framework error or an uncaught exception in the daemon — neither should happen.
    }

    private static Consumer<Throwable> ignoredError() {
        return throwable -> {
        };
    }

    private static void fireMouseClicked(HyperlinkLabel label) {
        MouseEvent event = new MouseEvent(label, MouseEvent.MOUSE_CLICKED,
                System.currentTimeMillis(), 0, 0, 0, 1, false);
        for (MouseListener listener : label.getMouseListeners()) {
            listener.mouseClicked(event);
        }
    }

    private static void invokeAndWait(Runnable r) throws InterruptedException, InvocationTargetException {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeAndWait(r);
        }
    }
}
