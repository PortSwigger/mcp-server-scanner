package com.mcpscanner.checks.api.crossidentity;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

public final class ProbeTriplet {

    private final ProbeTransport transport;
    private final DecisionLog log;
    private final Executor arms;

    public ProbeTriplet(ProbeTransport transport, DecisionLog log) {
        this(transport, log, Runnable::run);
    }

    public ProbeTriplet(ProbeTransport transport, DecisionLog log, Executor arms) {
        this.transport = transport;
        this.log = log;
        this.arms = arms;
    }

    public ProbeTriplet over(ProbeTransport otherTransport, DecisionLog otherLog) {
        return new ProbeTriplet(otherTransport, otherLog, arms);
    }

    public ProbeTriplet armsOn(Executor executor) {
        return new ProbeTriplet(transport, log, executor);
    }

    public Optional<Separation> separate(String probe, TripletArms arms) {
        CompletableFuture<Optional<OperationReply>> baselineArm = sampled(arms.baseline());
        CompletableFuture<Optional<OperationReply>> candidateArm = sampled(arms.candidate());
        CompletableFuture<Optional<OperationReply>> controlArm = sampled(arms.control());
        AwaitedTasks.awaitAll(List.of(baselineArm, candidateArm, controlArm));
        Optional<OperationReply> baseline = AwaitedTasks.joined(baselineArm);
        Optional<OperationReply> candidate = AwaitedTasks.joined(candidateArm);
        Optional<OperationReply> control = AwaitedTasks.joined(controlArm);
        if (transport.stopped()) {
            return Optional.empty();
        }
        if (baseline.isEmpty() || candidate.isEmpty() || control.isEmpty()) {
            log.record(probe + ":triplet_not_separated:unstable_arm");
            return Optional.empty();
        }
        String signature = candidate.get().signature();
        if (signature.equals(baseline.get().signature()) || signature.equals(control.get().signature())) {
            log.record(probe + ":triplet_not_separated");
            return Optional.empty();
        }
        return Optional.of(new Separation(baseline.get(), candidate.get(), control.get()));
    }

    private CompletableFuture<Optional<OperationReply>> sampled(HttpRequest request) {
        return CompletableFuture.supplyAsync(() -> stableArm(request), arms);
    }

    private Optional<OperationReply> stableArm(HttpRequest request) {
        OperationReply first = OperationReply.of(transport.sample(request));
        OperationReply second = OperationReply.of(transport.sample(request));
        boolean stable = first.answered() && second.answered() && first.signature().equals(second.signature());
        return stable ? Optional.of(first) : Optional.empty();
    }
}
