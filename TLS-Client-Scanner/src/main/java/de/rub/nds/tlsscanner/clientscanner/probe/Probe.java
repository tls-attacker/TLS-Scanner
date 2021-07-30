/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.probe;

import java.util.concurrent.Callable;

import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public interface Probe {

    /**
     * Whether it makes sense to execute this probe given the current report.
     *
     * @param  report
     *                The report so far
     * @return        Whether it makes sense to execute this probe.
     */
    public boolean canBeExecuted(ClientReport report);

    public Callable<ClientProbeResult> getCallable(ClientReport report);

    public ClientProbeResult getCouldNotExecuteResult(ClientReport report);
}