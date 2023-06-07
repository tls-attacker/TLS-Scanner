/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket.TicketResult;

public class SessionTicketProbeResult extends VersionDependentProbeResult<TicketResult> {
    public SessionTicketProbeResult() {
        super(ProbeType.SESSION_TICKET);
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.setSessionTicketProbeResult(this);

        // initialize to false - subresults will update it
        report.putResult(AnalyzedProperty.VERSION_CHANGE_TICKET, TestResult.FALSE);
        super.mergeData(report);
    }

}
