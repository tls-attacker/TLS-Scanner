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
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class HttpHeaderProbeIT extends AbstractProbeIT {

    public HttpHeaderProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "-www");
    }

    @Override
    protected boolean executedAsPlanned() {
        return report.getHeaderList().size() == 1
                && report.getHeaderList().get(0).getHeaderName().getValue().equals("Content-type")
                && report.getHeaderList().get(0).getHeaderValue().getValue().equals("text/html")
                && report.getHstsMaxAge() == null
                && report.getHpkpMaxAge() == null
                && report.getNormalHpkpPins().size() == 0
                && report.getReportOnlyHpkpPins().size() == 0
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_HTTPS, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_HSTS, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_HPKP, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.VULNERABLE_TO_BREACH, TestResults.FALSE);
    }

    @Override
    protected ProbeType getTestProbe() {
        return TlsProbeType.HTTP_HEADER;
    }
}
