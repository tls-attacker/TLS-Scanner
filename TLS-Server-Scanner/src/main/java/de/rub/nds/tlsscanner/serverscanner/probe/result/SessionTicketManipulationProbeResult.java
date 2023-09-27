/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.TicketManipulationResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class SessionTicketManipulationProbeResult
        extends VersionDependentProbeResult<TicketManipulationResult> {
    public SessionTicketManipulationProbeResult() {
        super(TlsProbeType.SESSION_TICKET_MANIPULATION);
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setSessionTicketManipulationResult(this);
        super.mergeData(report);
    }
}
