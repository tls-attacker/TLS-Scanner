/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.afterprobe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import de.rub.nds.signatureengine.keyparsers.PemUtil;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
        report.setCertificateChainList(null);
        probe.analyze(report);
        assertNull(report.getSupportedSignatureAndHashAlgorithmsCert());
    }

    @Test
    public void testEmptyCertificateChain() {
        report.setCertificateChainList(
                List.of(new CertificateChain(Certificate.EMPTY_CHAIN, "a.com")));
        probe.analyze(report);
        assertTrue(report.getSupportedSignatureAndHashAlgorithmsCert().isEmpty());
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
            report.setCertificateChainList(List.of(new CertificateChain(certificate, "a.com")));
            probe.analyze(report);
        } catch (IOException | URISyntaxException | CertificateException e) {
            fail("Could not load certificate from resources");
        }
        assertEquals(1, report.getSupportedSignatureAndHashAlgorithmsCert().size());
        assertTrue(
                report.getSupportedSignatureAndHashAlgorithmsCert()
                        .contains(SignatureAndHashAlgorithm.RSA_SHA256));
    }
}
