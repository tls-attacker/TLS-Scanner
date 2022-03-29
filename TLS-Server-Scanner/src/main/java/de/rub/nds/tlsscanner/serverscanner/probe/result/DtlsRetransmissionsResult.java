/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class DtlsRetransmissionsResult extends ProbeResult<ServerReport> {

    private TestResult sendsRetransmissions;
    private TestResult processesRetransmissions;

    public DtlsRetransmissionsResult(TestResult sendsRetransmissions, TestResult processesRetransmissions) {
        super(TlsProbeType.DTLS_RETRANSMISSIONS);
        this.sendsRetransmissions = sendsRetransmissions;
        this.processesRetransmissions = processesRetransmissions;

    }

    @Override
    protected void mergeData(ServerReport report) {
        report.putResult(TlsAnalyzedProperty.SENDS_RETRANSMISSIONS, sendsRetransmissions);
        report.putResult(TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS, processesRetransmissions);
    }

}
