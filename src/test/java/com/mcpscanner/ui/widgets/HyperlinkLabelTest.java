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
        HyperlinkLabel label = new HyperlinkLabel("docs", TARGET, recorded::set);

        invokeAndWait(() -> fireMouseClicked(label));

        assertThat(recorded.get()).isEqualTo(TARGET);
    }

    @Test
    void mouseClickedInvokesLauncherOffEdt() throws Exception {
        CountDownLatch fired = new CountDownLatch(1);
        AtomicReference<Boolean> firedOnEdt = new AtomicReference<>();
        HyperlinkLabel label = new HyperlinkLabel("docs", TARGET, uri -> new Thread(() -> {
            firedOnEdt.set(SwingUtilities.isEventDispatchThread());
            fired.countDown();
        }).start());

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
