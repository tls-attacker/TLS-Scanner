/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import static org.junit.Assert.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.signatureengine.keyparsers.PemUtil;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

import org.bouncycastle.crypto.tls.Certificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.List;

public class CertificateSignatureAndHashAlgorithmAfterProbeTest {

    private final String PATH_TO_CERTIFICATE = "certificates/cert.pem";

    private ServerReport report;
    private CertificateSignatureAndHashAlgorithmAfterProbe probe;

    @BeforeEach
    public void setup() {
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
                new ListResult<>(
                        List.of(new CertificateChainReport(Certificate.EMPTY_CHAIN, "a.com")),
                        TlsAnalyzedProperty.CERTIFICATE_CHAINS.name()));
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
            Certificate certificate = PemUtil.readCertificate(certificateFile);
            report.putResult(
                    TlsAnalyzedProperty.CERTIFICATE_CHAINS,
                    new ListResult<>(
                            List.of(new CertificateChainReport(certificate, "a.com")),
                            TlsAnalyzedProperty.CERTIFICATE_CHAINS.name()));
            probe.analyze(report);
        } catch (IOException | URISyntaxException | CertificateException e) {
            fail("Could not load certificate from resources");
        }
        assertEquals(1, report.getSupportedCertSignatureAlgorithms().size());
        assertTrue(
                report.getSupportedCertSignatureAlgorithms()
                        .contains(SignatureAndHashAlgorithm.RSA_SHA256));
    }
}
