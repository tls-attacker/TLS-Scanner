/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class TicketResultTls13 extends TicketResult {

    private TestResult earlyDataSupport;
    private TestResult earlyDataReplayVulnerable;

    protected TicketResultTls13(TestResult result) {
        super(ProtocolVersion.TLS13, result);
        this.earlyDataSupport = result;
        this.earlyDataReplayVulnerable = result;
    }

    @Override
    public void writeToSiteReportVersionSpecific(SiteReport report) {
        putResult(report, AnalyzedProperty.SUPPORTS_EARLY_DATA_TICKET, this.getEarlyDataSupport(), true);
        putResult(report, AnalyzedProperty.REPLAY_VULNERABLE_EARLY_DATA_TICKET, this.getEarlyDataReplayVulnerable(),
            true);
    }

    public TestResult getEarlyDataSupport() {
        return earlyDataSupport;
    }

    public void setEarlyDataSupport(TestResult earlyDataSupport) {
        this.earlyDataSupport = earlyDataSupport;
    }

    public TestResult getEarlyDataReplayVulnerable() {
        return earlyDataReplayVulnerable;
    }

    public void setEarlyDataReplayVulnerable(TestResult earlyDataReplayVulnerable) {
        this.earlyDataReplayVulnerable = earlyDataReplayVulnerable;
    }

}
