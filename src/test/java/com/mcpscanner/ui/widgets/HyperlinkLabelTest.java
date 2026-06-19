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

import static org.assertj.core.api.Assertions.assertThat;

class HyperlinkLabelTest {

    private static final URI TARGET = URI.create("https://example.com/docs");

    @Test
    void mouseClickedInvokesLauncherWithTargetUri() throws Exception {
        AtomicReference<URI> recorded = new AtomicReference<>();
        HyperlinkLabel.Launcher launcher = recorded::set;
        HyperlinkLabel label = new HyperlinkLabel("docs", TARGET, launcher);

        invokeAndWait(() -> fireMouseClicked(label));

        assertThat(recorded.get()).isEqualTo(TARGET);
    }

    @Test
    void browseFailureIsReportedToErrorSinkAndNotPropagated() throws Exception {
        RuntimeException failure = new RuntimeException("browse blew up");
        CountDownLatch reported = new CountDownLatch(1);
        AtomicReference<Throwable> recorded = new AtomicReference<>();
        HyperlinkLabel.Launcher launcher = HyperlinkLabel.daemonLauncher(
                uri -> {
                    throw failure;
                },
                throwable -> {
                    recorded.set(throwable);
                    reported.countDown();
                });
        HyperlinkLabel label = new HyperlinkLabel("docs", TARGET, launcher);

        invokeAndWait(() -> fireMouseClicked(label));

        assertThat(reported.await(1, TimeUnit.SECONDS)).isTrue();
        assertThat(recorded.get()).isSameAs(failure);
    }

    @Test
    void mouseClickedInvokesLauncherOffEdt() throws Exception {
        CountDownLatch fired = new CountDownLatch(1);
        AtomicReference<Boolean> firedOnEdt = new AtomicReference<>();
        HyperlinkLabel.Launcher launcher = uri -> new Thread(() -> {
            firedOnEdt.set(SwingUtilities.isEventDispatchThread());
            fired.countDown();
        }).start();
        HyperlinkLabel label = new HyperlinkLabel("docs", TARGET, launcher);

        invokeAndWait(() -> fireMouseClicked(label));

        assertThat(fired.await(1, TimeUnit.SECONDS)).isTrue();
        assertThat(firedOnEdt.get()).isFalse();
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
