package com.mcpscanner.checks.api.crossidentity;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.api.CheckLog;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

class ProbeTripletTest {

    private static final DecisionLog LOG = new DecisionLog(new CheckLog(McpEventLog.noop(), "check"), "tools/call t");
    private static final TripletArms ARMS = new TripletArms(FakeMcpTarget.toolCall("t", "{}", null),
            FakeMcpTarget.toolCall("t", "{}", "B"), FakeMcpTarget.toolCall("t", "{}", "C"));

    private final ExecutorService pool = Executors.newCachedThreadPool();
    private final ArmsMeeting armsMeeting = new ArmsMeeting();

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @AfterEach
    void stopPool() {
        pool.shutdownNow();
    }

    @Test
    void armsOnAPoolAreSampledAtTheSameTimeAndStillSeparate() {
        FakeMcpTarget target = new FakeMcpTarget(armsMeeting);

        var separation = new ProbeTriplet(new ProbeTransport(target.http(), LOG), LOG, pool).separate("probe", ARMS);

        assertThat(armsMeeting.mostInFlight()).isEqualTo(3);
        assertThat(separation).isPresent();
    }

    @Test
    void armsWithoutAPoolAreSampledTwiceEachInTurn() {
        FakeMcpTarget target = new FakeMcpTarget(ProbeTripletTest::replyTo);

        new ProbeTriplet(new ProbeTransport(target.http(), LOG), LOG).separate("probe", ARMS);

        assertThat(target.sent()).extracting(FakeMcpTarget::principal)
                .containsExactly(null, null, "B", "B", "C", "C");
    }

    @Test
    void aKitForAnotherPrincipalKeepsSamplingItsArmsOnThePool() {
        FakeMcpTarget target = new FakeMcpTarget(armsMeeting);
        ProbeKit kit = ProbeKit.of(OperationSeed.of(FakeMcpTarget.toolCall("t", "{}", "A")).orElseThrow(),
                TestPrincipals.owner(Optional.empty()), null, new ProbeTransport(target.http(), LOG),
                new AbsentValues(), LOG, new OpenedSessions()).armsOn(pool);

        kit.forPrincipal(TestPrincipals.peer("B")).triplet().separate("probe", ARMS);

        assertThat(armsMeeting.mostInFlight()).isEqualTo(3);
    }

    private static final class ArmsMeeting implements Function<HttpRequest, FakeReply> {

        private final CountDownLatch everyArmSampling = new CountDownLatch(3);
        private final AtomicInteger inFlight = new AtomicInteger();
        private final AtomicInteger mostInFlight = new AtomicInteger();

        @Override
        public FakeReply apply(HttpRequest request) {
            mostInFlight.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
            everyArmSampling.countDown();
            awaited(everyArmSampling);
            inFlight.decrementAndGet();
            return replyTo(request);
        }

        int mostInFlight() {
            return mostInFlight.get();
        }
    }

    private static FakeReply replyTo(HttpRequest request) {
        String principal = FakeMcpTarget.principal(request);
        return principal == null ? FakeReply.unauthorized() : FakeReply.result("note of " + principal);
    }

    private static boolean awaited(CountDownLatch latch) {
        try {
            return latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
