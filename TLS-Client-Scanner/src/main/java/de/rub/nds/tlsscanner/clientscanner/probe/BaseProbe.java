/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

import org.apache.logging.log4j.CloseableThreadContext;

import de.rub.nds.tlsscanner.clientscanner.client.Orchestrator;
import de.rub.nds.tlsscanner.clientscanner.dispatcher.BaseDispatcher;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.util.helper.ReverseIterator;

public abstract class BaseProbe extends BaseDispatcher implements Probe {
    protected static String PROBE_NAMESPACE = BaseProbe.class.getPackage().getName() + '.';
    protected Orchestrator orchestrator;
    private ProbeRequirements requirementsCache = null;
    private boolean areRequirementsChached = false;

    public BaseProbe(Orchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    // #region orchestrating side
    public String getHostnameForStandalone() {
        return getHostnamePrefix();
    }

    protected String getHostnamePrefix() {
        // hostname from class path
        String prefix = getClass().getName();
        if (prefix.startsWith(PROBE_NAMESPACE)) {
            prefix = prefix.substring(PROBE_NAMESPACE.length());
        }
        // reverse segments
        String[] segments = prefix.split("\\.");
        prefix = String.join(".", new ReverseIterator<>(segments));
        return prefix;
    }

    protected ClientProbeResult callInternal(ClientReport report, String hostnamePrefix) throws InterruptedException,
            ExecutionException {
        return orchestrator.runProbe(this, hostnamePrefix, report.uid, report, null);
    }

    public final ClientProbeResult call(ClientReport report) throws InterruptedException, ExecutionException {
        try (final CloseableThreadContext.Instance ctc = CloseableThreadContext.push(getClass().getSimpleName())) {
            return callInternal(report, getHostnamePrefix());
        }
    }

    @Override
    public Callable<ClientProbeResult> getCallable(ClientReport report) {
        return () -> call(report);
    }

    protected abstract ProbeRequirements getRequirements();

    protected ProbeRequirements getRequirementsCacheControlled() {
        if (!areRequirementsChached) {
            requirementsCache = getRequirements();
            if (requirementsCache == null) {
                requirementsCache = ProbeRequirements.TRUE();
            }
            areRequirementsChached = true;
        }
        return requirementsCache;
    }

    @Override
    public boolean canBeExecuted(ClientReport report) {
        return getRequirementsCacheControlled().evaluateRequirementsMet(report);
    }

    @Override
    public ClientProbeResult getCouldNotExecuteResult(ClientReport report) {
        return getRequirementsCacheControlled().evaluateWhyRequirementsNotMet(getClass(), report);
    }

    // #endregion
}