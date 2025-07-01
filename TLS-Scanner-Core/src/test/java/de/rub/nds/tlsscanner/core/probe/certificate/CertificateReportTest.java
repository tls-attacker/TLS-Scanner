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
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CertificateReportTest {

    @Test
    void testToStringWithSha256Fingerprint() {
        CertificateReport report = new CertificateReport();
        byte[] fingerprint =
                new byte[] {
                    0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
                };
        report.setSha256Fingerprint(fingerprint);

        String result = report.toString();
        assertNotNull(result);
        assertTrue(result.contains("Fingerprint: 01 23 45 67 89 AB CD EF"));
    }

    @Test
    void testToStringWithNullFingerprint() {
        CertificateReport report = new CertificateReport();
        report.setSha256Fingerprint(null);

        String result = report.toString();
        assertNotNull(result);
        assertTrue(result.contains("Fingerprint: null"));
    }

    @Test
    void testEqualsWithSameFingerprintArrays() {
        CertificateReport report1 = new CertificateReport();
        CertificateReport report2 = new CertificateReport();

        byte[] fingerprint1 = new byte[] {0x01, 0x02, 0x03};
        byte[] fingerprint2 = new byte[] {0x01, 0x02, 0x03};

        report1.setSha256Fingerprint(fingerprint1);
        report2.setSha256Fingerprint(fingerprint2);

        assertEquals(report1, report2);
    }

    @Test
    void testEqualsWithDifferentFingerprintArrays() {
        CertificateReport report1 = new CertificateReport();
        CertificateReport report2 = new CertificateReport();

        byte[] fingerprint1 = new byte[] {0x01, 0x02, 0x03};
        byte[] fingerprint2 = new byte[] {0x01, 0x02, 0x04};

        report1.setSha256Fingerprint(fingerprint1);
        report2.setSha256Fingerprint(fingerprint2);

        assertTrue(!report1.equals(report2));
    }

    @Test
    void testHashCodeWithFingerprint() {
        CertificateReport report1 = new CertificateReport();
        CertificateReport report2 = new CertificateReport();

        byte[] fingerprint = new byte[] {0x01, 0x02, 0x03};

        report1.setSha256Fingerprint(fingerprint);
        report2.setSha256Fingerprint(fingerprint.clone());

        // While not strictly required, objects that are equal should have the same hash code
        assertEquals(report1.hashCode(), report2.hashCode());
    }
}
