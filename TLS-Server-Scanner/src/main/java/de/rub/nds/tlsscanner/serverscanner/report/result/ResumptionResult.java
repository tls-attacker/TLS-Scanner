/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
    private final TestResult supportsTls13Psk;
    private final TestResult supportsTls13_0rtt;

    public ResumptionResult(TestResult supportsResumption, TestResult supportsTls13SessionTicket,
        TestResult supportsTls13PskDhe, TestResult supportsTls13Psk, TestResult supportsTls13_0rtt) {
        super(ProbeType.RESUMPTION);
        this.supportsResumption = supportsResumption;
        this.supportsTls13SessionTicket = supportsTls13SessionTicket;
        this.supportsTls13PskDhe = supportsTls13PskDhe;
        this.supportsTls13_0rtt = supportsTls13_0rtt;
        this.supportsTls13Psk = supportsTls13Psk;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.SUPPORTS_SESSION_IDS, supportsResumption);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS, supportsTls13SessionTicket);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_PSK_DHE, supportsTls13PskDhe);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_0_RTT, supportsTls13_0rtt);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_PSK, supportsTls13Psk);
    }

}
