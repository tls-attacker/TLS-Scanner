/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.TicketResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class SessionTicketProbeResult extends VersionDependentProbeResult<TicketResult> {
    public SessionTicketProbeResult() {
        super(TlsProbeType.SESSION_TICKET);
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setSessionTicketProbeResult(this);

        // initialize to false - subresults will update it
        report.putResult(TlsAnalyzedProperty.VERSION_CHANGE_TICKET, TestResults.FALSE);
        super.mergeData(report);
    }
}
