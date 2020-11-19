/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

/**
 *
 * @author robert
 */
public class ResumptionResult extends ProbeResult {

    private final TestResult supportsResumption;
    private final TestResult supportsTls13SessionTicket;
    private final TestResult supportsTls13PskDhe;

    public ResumptionResult(TestResult supportsResumption, TestResult supportsTls13SessionTicket,
            TestResult supportsTls13PskDhe) {
        super(ProbeType.RESUMPTION);
        this.supportsResumption = supportsResumption;
        this.supportsTls13SessionTicket = supportsTls13SessionTicket;
        this.supportsTls13PskDhe = supportsTls13PskDhe;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.SUPPORTS_SESSION_IDS, supportsResumption);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS, supportsTls13SessionTicket);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_PSK_DHE, supportsTls13PskDhe);
    }

}
