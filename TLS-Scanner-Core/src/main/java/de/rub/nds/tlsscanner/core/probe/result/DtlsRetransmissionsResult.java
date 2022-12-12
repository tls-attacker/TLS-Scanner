/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

public class DtlsRetransmissionsResult<Report extends TlsScanReport> extends ProbeResult<Report> {

    private TestResult sendsRetransmissions;
    private TestResult processesRetransmissions;

    public DtlsRetransmissionsResult(
            TestResult sendsRetransmissions, TestResult processesRetransmissions) {
        super(TlsProbeType.DTLS_RETRANSMISSIONS);
        this.sendsRetransmissions = sendsRetransmissions;
        this.processesRetransmissions = processesRetransmissions;
    }

    @Override
    protected void mergeData(Report report) {
        report.putResult(TlsAnalyzedProperty.SENDS_RETRANSMISSIONS, sendsRetransmissions);
        report.putResult(TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS, processesRetransmissions);
    }
}
