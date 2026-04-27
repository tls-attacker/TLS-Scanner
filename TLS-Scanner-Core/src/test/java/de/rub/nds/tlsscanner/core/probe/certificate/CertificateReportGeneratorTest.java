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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertificateReportGeneratorTest {

    private static final String EC_CERT_PEM =
            """
            -----BEGIN CERTIFICATE-----
            MIIB+TCCAX2gAwIBAgIBAzALBgcqhkjOPQQBBQAwQzELMAkGA1UEBhMCREUxDDAK
            BgNVBAoMA1JVQjEmMCQGA1UECwwdVExTLVNjYW5uZXIgQ0NBIEVDIFJPT1QtQ0Eg
            djMwHhcNMTkxMjEyMDAwMDAwWhcNMjAxMjE5MDAwMDAwWjBDMQswCQYDVQQGEwJE
            RTEMMAoGA1UECgwDUlVCMSYwJAYDVQQLDB1UTFMtU2Nhbm5lciBDQ0EgRUMgUk9P
            VC1DQSB2MzB2MBAGByqGSM49AgEGBSuBBAAiA2IABLTerq2BEf6vMtd+0TDlRRX3
            Zd5g7rkfVEh14ruE+7viaX3GftqvYADqYfQJ+w039kDypJjaF/nxdF9MXFEtxqoi
            a4hBUPPpNG8pZ4x5esCdceXrSfCJu2EQ783CvaY+FaNEMEIwCgYDVR0OBAMEAQEw
            DwYDVR0jAQEABAUwA4ABATAPBgNVHQ8BAf8EBQMDBwQAMBIGA1UdEwEB/wQIMAYB
            Af8CAQUwCwYHKoZIzj0EAQUAA2kAMGYCMQCH/EVdv5XufeWKBgggQoRkmGxuT7gl
            RICHwsTciIzE5YgjoL36wEHNET7m9YDyTJcCMQDE1KyPbkl27jrYWFaDHBIVqVXz
            /JBphRdLImHpK5dCF1MrwW5FEhMvo1/z3J549cY=
            -----END CERTIFICATE-----
            """;

    @BeforeEach
    void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void generateReport_ecCertificate_setsNamedCurve() throws IOException {
        ByteArrayInputStream certStream =
                new ByteArrayInputStream(EC_CERT_PEM.getBytes(StandardCharsets.US_ASCII));

        X509CertificateChain chain = CertificateIo.readPemChain(certStream);
        assertNotNull(chain, "Certificate chain should not be null");

        X509Certificate leafCert = chain.getCertificateList().get(0);
        CertificateReport report = CertificateReportGenerator.generateReport(leafCert);

        assertNotNull(report.getNamedCurve(), "EC certificates should populate the named curve");
        assertEquals(X509NamedCurve.SECP384R1, report.getNamedCurve());
    }
}
