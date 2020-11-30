/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Observable;
import java.util.Observer;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;

import org.apache.logging.log4j.CloseableThreadContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsscanner.clientscanner.client.ClientInfo;
import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.probe.Probe;
import de.rub.nds.tlsscanner.clientscanner.probe.after.IAfterProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.result.NotExecutedResult;

public class ClientScanExecutor implements Observer {
    private static final Logger LOGGER = LogManager.getLogger();

    private Collection<Probe> notScheduledTasks;
    private Collection<IAfterProbe> afterProbes;

    private Collection<ProbeAndResultFuture> futureResults;

    private final ExecutorService executor;
    private final Orchestrator orchestrator;

    public ClientScanExecutor(Collection<Probe> probesToRun, Collection<IAfterProbe> afterProbesToRun,
            Orchestrator orchestrator, ExecutorService executor) {
        this.notScheduledTasks = new ArrayList<>(probesToRun);
        this.afterProbes = afterProbesToRun;
        this.futureResults = new LinkedList<>();
        this.executor = executor;
        this.orchestrator = orchestrator;
    }

    public ClientReport execute() {
        ClientInfo clientInfo = orchestrator.getReportInformation();
        try (final CloseableThreadContext.Instance ctc = CloseableThreadContext.push(clientInfo.toShortString())) {
            orchestrator.start();
            ClientReport report = executeInternal(clientInfo);
            return report;
        } finally {
            orchestrator.cleanup();
        }
    }

    protected ClientReport executeInternal(ClientInfo clientInfo) {
        ClientReport report = new ClientReport(clientInfo);
        try {
            LOGGER.info("Starting scan");
            report.addObserver(this);
            checkForExecutableProbes(report);
            executeProbesTillNoneCanBeExecuted(report);
            report.deleteObserver(this);
            updateClientReporttWithNotExecutedProbes(report);
            reportAboutNotExecutedProbes(report);
            collectStatistics(report);
            executeAfterProbes(report);
            LOGGER.info("Finished scan");
            return report;
        } finally {
            report.finalizeReport();
        }
    }

    private void checkForExecutableProbes(ClientReport report) {
        update(report, null);
    }

    @SuppressWarnings("squid:S3776")
    // sonarlint: Cognitive Complexity of methods should not be too high
    private void executeProbesTillNoneCanBeExecuted(ClientReport report) {
        do {
            long lastMerge = System.currentTimeMillis();
            List<ProbeAndResultFuture> finishedFutures = new LinkedList<>();
            // iterate over a copy because somehow I failed to use synchronized
            // to exclusively lock out this loop from the update function
            // even using synchronized on this or the list did not work...
            for (ProbeAndResultFuture probeAndResultFuture : new ArrayList<>(futureResults)) {
                Future<ClientProbeResult> result = probeAndResultFuture.future;
                if (result.isDone()) {
                    lastMerge = System.currentTimeMillis();
                    try {
                        ClientProbeResult probeResult = result.get();
                        finishedFutures.add(probeAndResultFuture);
                        // TODO
                        // report.markProbeAsExecuted(result.get().getType())
                        if (probeResult != null) {
                            LOGGER.info("+++ {} executed", probeAndResultFuture.probe);
                            probeResult.merge(report);
                        } else {
                            LOGGER.error("Got null result from probe {}", probeAndResultFuture.probe);
                        }

                    } catch (Exception ex) {
                        LOGGER.error("Encountered an exception before we could merge the result. Killing the task.",
                                ex);
                        result.cancel(true);
                        finishedFutures.add(probeAndResultFuture);
                    }
                }

                if (lastMerge + 1000 * 60 * 30 < System.currentTimeMillis()) {
                    LOGGER.error(
                            "Last result merge is more than 30 minutes ago. Starting to kill threads to unblock...");
                    try {
                        ClientProbeResult probeResult = result.get(1, TimeUnit.MINUTES);
                        finishedFutures.add(probeAndResultFuture);
                        probeResult.merge(report);
                    } catch (Exception ex) {
                        result.cancel(true);
                        finishedFutures.add(probeAndResultFuture);
                        LOGGER.error("Killed task", ex);
                    }
                }
            }
            futureResults.removeAll(finishedFutures);
            report.markAsChangedAndNotify();
        } while (!futureResults.isEmpty());
    }

    private void updateClientReporttWithNotExecutedProbes(ClientReport report) {
        for (Probe probe : notScheduledTasks) {
            probe.getCouldNotExecuteResult(report).merge(report);
        }
    }

    @SuppressWarnings("squid:S3776")
    // sonarlint says this function is too complicated
    // this is mostly due to the nesting introduced by the outermost if
    private void reportAboutNotExecutedProbes(ClientReport report) {
        if (LOGGER.isWarnEnabled() && !notScheduledTasks.isEmpty()) {
            final int LIMIT_REASONS_NUM = 10;
            Map<Class<? extends Probe>, List<NotExecutedResult>> neReasons = new HashMap<>();
            Map<Class<? extends Probe>, Integer> notExecuted = new HashMap<>();

            BiFunction<Class<? extends Probe>, Integer, Integer> mapFunc = ((p, i) -> i == null ? 1 : i + 1);

            for (Probe probe : notScheduledTasks) {
                Class<? extends Probe> clazz = probe.getClass();
                int num = notExecuted.compute(clazz, mapFunc);
                if (num == 1) {
                    neReasons.computeIfAbsent(clazz, k -> new LinkedList<>());
                }
                if (neReasons.get(clazz).size() < LIMIT_REASONS_NUM) {
                    ClientProbeResult res = probe.getCouldNotExecuteResult(report);
                    if (res instanceof NotExecutedResult) {
                        neReasons.get(clazz).add((NotExecutedResult) res);
                    }
                }
            }

            LOGGER.warn("Did not execute the following probes:");
            for (Entry<Class<? extends Probe>, Integer> kvp : notExecuted.entrySet()) {
                LOGGER.warn("{}x {}", kvp.getValue(), kvp.getKey().getName());
                LOGGER.warn("Reasons (limited to {}):", LIMIT_REASONS_NUM);
                for (NotExecutedResult res : neReasons.get(kvp.getKey())) {
                    LOGGER.warn("Reason {}", res.message);
                }
            }
        }
    }

    private void collectStatistics(ClientReport report) {
        // TODO
    }

    private void executeAfterProbes(ClientReport report) {
        LOGGER.debug("Analyzing data...");
        if (afterProbes != null) {
            for (IAfterProbe afterProbe : afterProbes) {
                afterProbe.analyze(report);
            }
        }
        LOGGER.debug("Finished analysis");
    }

    @Override
    public synchronized void update(Observable o, Object arg) {
        if (o != null && o instanceof ClientReport) {
            ClientReport report = (ClientReport) o;
            // iterate over a copy of the list, as we might remove elements
            for (Probe probe : new ArrayList<>(notScheduledTasks)) {
                if (probe.canBeExecuted(report)) {
                    notScheduledTasks.remove(probe);
                    Callable<ClientProbeResult> callable = probe.getCallable(report);
                    Future<ClientProbeResult> future = executor.submit(callable);
                    futureResults.add(new ProbeAndResultFuture(probe, future));
                }
            }
        } else {
            LOGGER.error("Received an update from a non-ClientReport");
        }
    }

    protected static class ProbeAndResultFuture {
        public final Probe probe;
        public final Future<ClientProbeResult> future;

        public ProbeAndResultFuture(Probe probe, Future<ClientProbeResult> future) {
            this.probe = probe;
            this.future = future;
        }
    }
}