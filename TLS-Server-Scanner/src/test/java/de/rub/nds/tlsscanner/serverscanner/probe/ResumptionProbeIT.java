/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.constants.ProbeType;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class ResumptionProbeIT extends AbstractProbeIT {

    public ResumptionProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected boolean executedAsPlanned() {
        return verifyProperty(TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION, TestResults.TRUE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION, TestResults.TRUE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_TLS13_PSK, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION,
                        TestResults.NOT_TESTED_YET)
                && verifyProperty(
                        TlsAnalyzedProperty
                                .SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION,
                        TestResults.NOT_TESTED_YET)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_EXCHANGE_MODES, TestResults.TRUE);
    }

    @Override
    protected ProbeType getTestProbe() {
        return TlsProbeType.RESUMPTION;
    }

    @Override
    protected List<ProbeType> getRequiredProbes() {
        return Arrays.asList(TlsProbeType.PROTOCOL_VERSION, TlsProbeType.CIPHER_SUITE);
    }
}
