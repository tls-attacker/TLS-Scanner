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
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Tag;

@Tag(TestCategories.INTEGRATION_TEST)
public class CipherSuiteProbeIT extends AbstractProbeIT {

    public CipherSuiteProbeIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Override
    protected TlsServerProbe getProbe() {
        return new CipherSuiteProbe(configSelector, parallelExecutor);
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
        List<CipherSuite> expectedCiphers =
                Arrays.asList(
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                        CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                        CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                        CipherSuite.TLS_AES_128_GCM_SHA256,
                        CipherSuite.TLS_AES_256_GCM_SHA384,
                        CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
        Set<CipherSuite> supportedCiphers = report.getSupportedCipherSuites();
        return expectedCiphers.size() == supportedCiphers.size()
                && expectedCiphers.containsAll(
                        supportedCiphers.stream().collect(Collectors.toList()))
                && report.getVersionSuitePairs().size() == 4
                && report.getVersionSuitePairs().get(0).getVersion() == ProtocolVersion.TLS10
                && report.getVersionSuitePairs().get(0).getCipherSuiteList().size() == 6
                && report.getVersionSuitePairs().get(1).getVersion() == ProtocolVersion.TLS11
                && report.getVersionSuitePairs().get(1).getCipherSuiteList().size() == 6
                && report.getVersionSuitePairs().get(2).getVersion() == ProtocolVersion.TLS12
                && report.getVersionSuitePairs().get(2).getCipherSuiteList().size() == 20
                && report.getVersionSuitePairs().get(3).getVersion() == ProtocolVersion.TLS13
                && report.getVersionSuitePairs().get(3).getCipherSuiteList().size() == 3
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_ANON, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_EXPORT, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_DES, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_SEED, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_IDEA, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_RC2, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_RC4, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_3DES, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_POST_QUANTUM, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_AEAD, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_PFS, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_ONLY_PFS, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_AES, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_CAMELLIA, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_ARIA, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_CHACHA, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_RSA, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_STATIC_DH, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_DHE, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_ECDSA, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_RSA_CERT, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_DSS, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_ECDHE, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_GOST, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_SRP, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_KERBEROS, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_PSK_RSA, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_PSK_DHE, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_FORTEZZA, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_NEWHOPE, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_ECMQV, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.PREFERS_PFS, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS, TestResults.FALSE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_LEGACY_PRF, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_SHA256_PRF, TestResults.TRUE)
                && verifyProperty(TlsAnalyzedProperty.SUPPORTS_SHA384_PRF, TestResults.TRUE);
    }
}
