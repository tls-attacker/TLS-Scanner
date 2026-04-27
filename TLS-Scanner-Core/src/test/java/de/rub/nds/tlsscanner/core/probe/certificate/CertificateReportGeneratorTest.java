/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.filesystem.CertificateIo;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertificateReportGeneratorTest {

    private static final String EC_CERT_PATH = "certificates/ecrootv3.pem";

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void generateReport_ecCertificate_setsNamedCurve() throws IOException {
        InputStream certStream =
                CertificateReportGeneratorTest.class
                        .getClassLoader()
                        .getResourceAsStream(EC_CERT_PATH);
        assertNotNull(certStream, "EC certificate test resource not found: " + EC_CERT_PATH);

        X509CertificateChain chain = CertificateIo.readPemChain(certStream);
        assertNotNull(chain, "Certificate chain should not be null");

        X509Certificate leafCert = chain.getCertificateList().get(0);
        CertificateReport report = CertificateReportGenerator.generateReport(leafCert);

        assertNotNull(report.getNamedCurve(), "EC certificates should populate the named curve");
        assertEquals(X509NamedCurve.SECP384R1, report.getNamedCurve());
    }
}
