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
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

public class TicketResultTls13 extends TicketResult {

    private TestResults earlyDataSupport;
    private TestResults earlyDataReplayVulnerable;

    protected TicketResultTls13(TestResults result) {
        super(ProtocolVersion.TLS13, result);
        this.earlyDataSupport = result;
        this.earlyDataReplayVulnerable = result;
    }

    @Override
    public void writeToServerReportVersionSpecific(ServerReport report) {
        putResult(
                report,
                TlsAnalyzedProperty.SUPPORTS_EARLY_DATA_TICKET,
                this.getEarlyDataSupport(),
                true);
        putResult(
                report,
                TlsAnalyzedProperty.REPLAY_VULNERABLE_EARLY_DATA_TICKET,
                this.getEarlyDataReplayVulnerable(),
                true);
    }

    public TestResults getEarlyDataSupport() {
        return earlyDataSupport;
    }

    public void setEarlyDataSupport(TestResults earlyDataSupport) {
        this.earlyDataSupport = earlyDataSupport;
    }

    public TestResults getEarlyDataReplayVulnerable() {
        return earlyDataReplayVulnerable;
    }

    public void setEarlyDataReplayVulnerable(TestResults earlyDataReplayVulnerable) {
        this.earlyDataReplayVulnerable = earlyDataReplayVulnerable;
    }
}
