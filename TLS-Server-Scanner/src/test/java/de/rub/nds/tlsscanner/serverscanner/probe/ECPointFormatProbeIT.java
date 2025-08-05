/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class ECPointFormatProbeIT extends AbstractProbeIT {

    public ECPointFormatProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected TlsServerProbe getProbe() {
        return new ECPointFormatProbe(configSelector, parallelExecutor);
    }

    @Override
    protected void prepareReport() {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3, TestResults.TRUE);
    }

    @Override
    protected boolean executedAsPlanned() {
        return verifyProperty(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, TestResults.TRUE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, TestResults.TRUE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.HANDSHAKES_WITH_UNDEFINED_POINT_FORMAT,
                        TestResults.TRUE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION, TestResults.TRUE);
    }
}
