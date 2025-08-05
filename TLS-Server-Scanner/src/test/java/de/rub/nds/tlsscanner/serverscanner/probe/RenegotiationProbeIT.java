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
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class RenegotiationProbeIT extends AbstractProbeIT {

    public RenegotiationProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected TlsServerProbe getProbe() {
        return new RenegotiationProbe(configSelector, parallelExecutor);
    }

    @Override
    protected void prepareReport() {
        Set<CipherSuite> supportedCiphers = new HashSet<>();
        supportedCiphers.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        report.putResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES, supportedCiphers);
    }

    @Override
    protected boolean executedAsPlanned() {
        return verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION,
                        TestResults.TRUE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_CIPHERSUITE,
                        TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION,
                        TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V1,
                        TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V2,
                        TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V1,
                        TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V2,
                        TestResults.FALSE)
                && verifyProperty(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_RENEGOTIATION,
                        TestResults.NOT_TESTED_YET);
    }
}
