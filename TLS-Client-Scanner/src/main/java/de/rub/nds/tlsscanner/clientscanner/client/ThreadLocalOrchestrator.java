/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.client;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ThreadPoolExecutor;

import de.rub.nds.tlsscanner.clientscanner.config.ClientScannerConfig;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.Dispatcher;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class ThreadLocalOrchestrator implements Orchestrator {
    protected final ClientScannerConfig csConfig;
    private boolean isStarted = false;
    private boolean isCleanedUp = false;

    private DefaultOrchestrator unassignedOrchestrator = null;
    @SuppressWarnings("squid:S5164")
    // sonarlint: Call "remove()" on "localOrchestrator".
    // We cannot get each thread from the pool executor to call remove
    // Our solution is to cleanup each Orchestrator (using allOrchestrators) one
    // by one and setting localOrchestrator to null. This is by no means perfect
    // and is a memory leak for each thread, as we do not remove our threadLocal
    // from each Thread.threadLocals. But as the threads *should* not live much
    // longer anyway, this *should* not be a problem.
    // If this turns out to be a problem, I guess we should use reflection to
    // access each threads threadLocals and remove our localOrchestrator from
    // there
    private ThreadLocal<DefaultOrchestrator> localOrchestrator;
    private final List<DefaultOrchestrator> allOrchestrators = new ArrayList<>();
    protected final ThreadPoolExecutor secondaryExecutor;

    public ThreadLocalOrchestrator(ClientScannerConfig csConfig, ThreadPoolExecutor secondaryExecutor) {
        this.csConfig = csConfig;
        this.secondaryExecutor = secondaryExecutor;
    }

    // just so we have the same signature as the normal Orchestrator
    public ThreadLocalOrchestrator(ClientScannerConfig csConfig, ThreadPoolExecutor secondaryExecutor, int _ignored) {
        this(csConfig, secondaryExecutor);
    }

    @Override
    public ThreadPoolExecutor getSecondaryExecutor() {
        return secondaryExecutor;
    }

    @Override
    public ClientScannerConfig getCSConfig() {
        return csConfig;
    }

    protected DefaultOrchestrator createOrchestrator() {
        DefaultOrchestrator ret = new DefaultOrchestrator(csConfig, secondaryExecutor, 2);
        allOrchestrators.add(ret);
        if (isStarted) {
            ret.start();
        }
        if (isCleanedUp) {
            ret.cleanup();
        }
        return ret;
    }

    protected DefaultOrchestrator getAnyOrchestrator() {
        DefaultOrchestrator ret = null;
        synchronized (this) {
            if (allOrchestrators.isEmpty()) {
                unassignedOrchestrator = createOrchestrator();
                ret = unassignedOrchestrator;
            } else {
                ret = allOrchestrators.get(0);
            }
        }
        return ret;
    }

    protected DefaultOrchestrator getLocalOrchestrator() {
        DefaultOrchestrator ret = localOrchestrator.get();
        if (ret == null) {
            synchronized (this) {
                // check if we have one unassigned orch which we can reuse
                if (unassignedOrchestrator != null) {
                    ret = unassignedOrchestrator;
                    unassignedOrchestrator = null;
                }
            }
            if (ret == null) {
                // no unassigned orch - create a new one
                ret = createOrchestrator();
            }
            localOrchestrator.set(ret);
        }
        return ret;
    }

    @Override
    public ClientInfo getReportInformation() {
        return getAnyOrchestrator().getReportInformation();
    }

    @Override
    public void start() {
        if (isStarted) {
            throw new IllegalStateException("Orchestrator is already started");
        }
        isStarted = true;
        localOrchestrator = new ThreadLocal<>();
        for (DefaultOrchestrator o : allOrchestrators) {
            o.start();
        }
    }

    @Override
    public void cleanup() {
        if (!isStarted) {
            throw new IllegalStateException("Orchestrator is not yet started");
        }
        if (isCleanedUp) {
            throw new IllegalStateException("Orchestrator is already cleaned up");
        }
        isCleanedUp = true;
        for (DefaultOrchestrator o : new ArrayList<DefaultOrchestrator>(allOrchestrators)) {
            o.cleanup();
            allOrchestrators.remove(o);
        }
        localOrchestrator = null;
    }

    @Override
    public ClientProbeResult runDispatcher(Dispatcher probe, String hostnamePrefix, ClientReport report,
        Object additionalParameters) throws InterruptedException, ExecutionException {
        return getLocalOrchestrator().runDispatcher(probe, hostnamePrefix, report, additionalParameters);
    }
}