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
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket.TicketManipulationResult;

public class SessionTicketManipulationProbeResult extends VersionDependentProbeResult<TicketManipulationResult> {
    public SessionTicketManipulationProbeResult() {
        super(ProbeType.SESSION_TICKET_MANIPULATION);
    }

    @Override
    protected void mergeData(SiteReport report) {
        report.setSessionTicketManipulationResult(this);
        super.mergeData(report);
    }
}
