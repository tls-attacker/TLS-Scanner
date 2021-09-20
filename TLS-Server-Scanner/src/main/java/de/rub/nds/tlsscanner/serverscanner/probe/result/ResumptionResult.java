/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.result;

import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

/**
 *
 * @author robert
 */
public class ResumptionResult extends ProbeResult<ServerReport> {

    private final TestResult supportsResumption;
    private final TestResult supportsSessionTicketResumption;
    private final TestResult supportsTls13SessionTicket;
    private final TestResult supportsTls13PskDhe;
    private final TestResult supportsTls13Psk;
    private final TestResult supportsTls13_0rtt;
    private final TestResult supportsDtlsCookieExchangeInResumption;
    private final TestResult supportsDtlsCookieExchangeInSessionTicketResumption;
    private final TestResult respectsPskModes;

    public ResumptionResult(TestResult supportsResumption, TestResult supportsTicketResumption,
        TestResult supportsTls13SessionTicket, TestResult supportsTls13PskDhe, TestResult supportsTls13Psk,
        TestResult supportsTls13_0rtt, TestResult supportsDtlsCookieExchangeInResumption,
        TestResult supportsDtlsCookieExchangeInTicketResumption, TestResult respectsPskModes) {
        super(ProbeType.RESUMPTION);
        this.supportsResumption = supportsResumption;
        this.supportsSessionTicketResumption = supportsTicketResumption;
        this.supportsTls13SessionTicket = supportsTls13SessionTicket;
        this.supportsTls13PskDhe = supportsTls13PskDhe;
        this.supportsTls13_0rtt = supportsTls13_0rtt;
        this.supportsTls13Psk = supportsTls13Psk;
        this.supportsDtlsCookieExchangeInResumption = supportsDtlsCookieExchangeInResumption;
        this.supportsDtlsCookieExchangeInSessionTicketResumption = supportsDtlsCookieExchangeInTicketResumption;
        this.respectsPskModes = respectsPskModes;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION, supportsResumption);
        report.putResult(AnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION, supportsSessionTicketResumption);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS, supportsTls13SessionTicket);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_PSK_DHE, supportsTls13PskDhe);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_0_RTT, supportsTls13_0rtt);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_PSK, supportsTls13Psk);
        report.putResult(AnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION,
            supportsDtlsCookieExchangeInResumption);
        report.putResult(AnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION,
            supportsDtlsCookieExchangeInSessionTicketResumption);
        report.putResult(AnalyzedProperty.SUPPORTS_TLS13_PSK_EXCHANGE_MODES, respectsPskModes);
    }

}
