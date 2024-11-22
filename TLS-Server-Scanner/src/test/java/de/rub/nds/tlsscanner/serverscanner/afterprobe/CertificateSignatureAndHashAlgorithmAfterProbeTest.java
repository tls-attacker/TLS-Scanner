/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.filesystem.CertificateIo;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.Security;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CertificateSignatureAndHashAlgorithmAfterProbeTest {

    private final String PATH_TO_CERTIFICATE = "certificates/cert.pem";

    private ServerReport report;
    private CertificateSignatureAndHashAlgorithmAfterProbe probe;

    @BeforeEach
    public void setup() {
        Security.addProvider(new BouncyCastleProvider());
        report = new ServerReport();
        probe = new CertificateSignatureAndHashAlgorithmAfterProbe();
    }

    @Test
    public void testMissingCertificateChain() {
        probe.analyze(report);
        assertNull(report.getSupportedCertSignatureAlgorithms());
    }

    @Test
    public void testEmptyCertificateChain() {
        report.putResult(
                TlsAnalyzedProperty.CERTIFICATE_CHAINS,
                List.of(new CertificateChainReport(new X509CertificateChain(), "a.com")));
        probe.analyze(report);
        assertTrue(report.getSupportedCertSignatureAlgorithms().isEmpty());
    }

    @Test
    public void testSingleCertificate() {
        try {
            File certificateFile =
                    new File(
                            CertificateSignatureAndHashAlgorithmAfterProbeTest.class
                                    .getClassLoader()
                                    .getResource(PATH_TO_CERTIFICATE)
                                    .toURI());
            X509CertificateChain chain = CertificateIo.readPemChain(certificateFile);
            CertificateChainReport chainReport = new CertificateChainReport(chain, "a.com");
            report.putResult(TlsAnalyzedProperty.CERTIFICATE_CHAINS, List.of(chainReport));
            probe.analyze(report);
        } catch (IOException | URISyntaxException e) {
            fail("Could not load certificate from resources");
        }
        assertEquals(1, report.getSupportedCertSignatureAlgorithms().size());
        assertTrue(
                report.getSupportedCertSignatureAlgorithms()
                        .contains(X509SignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION));
    }
}
