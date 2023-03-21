/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class ConnectionClosingResult extends ProbeResult<ServerReport> {

    private final long closedAfterFinishedDelta;
    private final long closedAfterAppDataDelta;

    public ConnectionClosingResult(long closedAfterFinishedDelta, long closedAfterAppDataDelta) {
        super(TlsProbeType.CONNECTION_CLOSING_DELTA);
        this.closedAfterFinishedDelta = closedAfterFinishedDelta;
        this.closedAfterAppDataDelta = closedAfterAppDataDelta;
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setClosedAfterAppDataDelta(closedAfterAppDataDelta);
        report.setClosedAfterFinishedDelta(closedAfterFinishedDelta);
    }
}
