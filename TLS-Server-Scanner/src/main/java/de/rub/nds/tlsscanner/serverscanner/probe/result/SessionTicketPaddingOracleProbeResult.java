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
import de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket.TicketPaddingOracleResult;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class SessionTicketPaddingOracleProbeResult
        extends VersionDependentProbeResult<TicketPaddingOracleResult> {
    public SessionTicketPaddingOracleProbeResult() {
        super(TlsProbeType.SESSION_TICKET_PADDING_ORACLE);
    }

    @Override
    protected void mergeData(ServerReport report) {
        report.setSessionTicketPaddingOracleResult(this);
        super.mergeData(report);
    }
}
