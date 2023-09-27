/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class TicketResultPre13 extends TicketResult {

    protected TicketResultPre13(ProtocolVersion version, TestResults result) {
        super(version, result);
    }

    @Override
    public void writeToServerReportVersionSpecific(ServerReport report) {
        // no additional properties
    }
}
