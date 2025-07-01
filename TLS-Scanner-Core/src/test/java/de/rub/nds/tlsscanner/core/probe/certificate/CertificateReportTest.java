/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.certificate;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class CertificateReportTest {

    @Test
    void testEqualsWithSameSha256Fingerprint() {
        CertificateReport report1 = new CertificateReport();
        CertificateReport report2 = new CertificateReport();

        byte[] fingerprint = new byte[] {1, 2, 3, 4, 5};
        report1.setSha256Fingerprint(fingerprint);
        report2.setSha256Fingerprint(fingerprint.clone());

        assertEquals(report1, report2);
    }

    @Test
    void testEqualsWithDifferentSha256Fingerprint() {
        CertificateReport report1 = new CertificateReport();
        CertificateReport report2 = new CertificateReport();

        report1.setSha256Fingerprint(new byte[] {1, 2, 3, 4, 5});
        report2.setSha256Fingerprint(new byte[] {5, 4, 3, 2, 1});

        assertNotEquals(report1, report2);
    }

    @Test
    void testEqualsWithNullSha256Fingerprint() {
        CertificateReport report1 = new CertificateReport();
        CertificateReport report2 = new CertificateReport();

        report1.setSha256Fingerprint(null);
        report2.setSha256Fingerprint(null);

        assertEquals(report1, report2);
    }

    @Test
    void testEqualsWithOneNullSha256Fingerprint() {
        CertificateReport report1 = new CertificateReport();
        CertificateReport report2 = new CertificateReport();

        report1.setSha256Fingerprint(new byte[] {1, 2, 3});
        report2.setSha256Fingerprint(null);

        assertNotEquals(report1, report2);
    }

    @Test
    void testHashCodeWithSameSha256Fingerprint() {
        CertificateReport report1 = new CertificateReport();
        CertificateReport report2 = new CertificateReport();

        byte[] fingerprint = new byte[] {1, 2, 3, 4, 5};
        report1.setSha256Fingerprint(fingerprint);
        report2.setSha256Fingerprint(fingerprint.clone());

        assertEquals(report1.hashCode(), report2.hashCode());
    }

    @Test
    void testHashCodeWithDifferentSha256Fingerprint() {
        CertificateReport report1 = new CertificateReport();
        CertificateReport report2 = new CertificateReport();

        report1.setSha256Fingerprint(new byte[] {1, 2, 3, 4, 5});
        report2.setSha256Fingerprint(new byte[] {5, 4, 3, 2, 1});

        // Hash codes may be equal by chance, but with different arrays they should typically differ
        // This is not a strict requirement but good practice
        assertNotEquals(report1.hashCode(), report2.hashCode());
    }
}
