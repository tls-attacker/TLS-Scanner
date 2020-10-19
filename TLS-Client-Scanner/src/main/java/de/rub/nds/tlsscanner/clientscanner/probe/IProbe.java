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

import de.rub.nds.tlsscanner.clientscanner.dispatcher.IDispatcher;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public interface IProbe extends IDispatcher {

    /**
     * Whether it makes sense to execute this probe given the current report.
     *
     * @param report
     *            The report so far
     * @return Whether it makes sense to execute this probe.
     */
    public boolean canBeExecuted(ClientReport report);

    public Callable<ClientProbeResult> getCallable(ClientReport report);

    public ClientProbeResult getCouldNotExecuteResult(ClientReport report);
}