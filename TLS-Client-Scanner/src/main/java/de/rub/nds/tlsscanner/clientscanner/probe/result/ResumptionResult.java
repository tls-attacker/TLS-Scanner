/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;

public class ResumptionResult extends ProbeResult<ClientReport> {

    private final TestResult supportsResumption;
    private final TestResult supportsSessionTicketResumption;
    private final TestResult supportsDtlsCookieExchangeInResumption;
    private final TestResult supportsDtlsCookieExchangeInSessionTicketResumption;

    public ResumptionResult(
            TestResult supportsResumption,
            TestResult supportsTicketResumption,
            TestResult supportsDtlsCookieExchangeInResumption,
            TestResult supportsDtlsCookieExchangeInTicketResumption) {
        super(TlsProbeType.RESUMPTION);
        this.supportsResumption = supportsResumption;
        this.supportsSessionTicketResumption = supportsTicketResumption;
        this.supportsDtlsCookieExchangeInResumption = supportsDtlsCookieExchangeInResumption;
        this.supportsDtlsCookieExchangeInSessionTicketResumption =
                supportsDtlsCookieExchangeInTicketResumption;
    }

    @Override
    protected void mergeData(ClientReport report) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION, supportsResumption);
        report.putResult(
                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION,
                supportsSessionTicketResumption);
        report.putResult(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION,
                supportsDtlsCookieExchangeInResumption);
        report.putResult(
                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION,
                supportsDtlsCookieExchangeInSessionTicketResumption);
    }
}
