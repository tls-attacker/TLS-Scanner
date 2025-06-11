/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.ECPointFormatUncompressedOnlyCheck;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Collections;
import org.junit.jupiter.api.Test;

public class ECPointFormatUncompressedOnlyCheckTest {

    @Test
    public void testPositive() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS,
                Collections.singleton(ExtensionType.EC_POINT_FORMATS));
        report.putResult(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, TestResults.FALSE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, TestResults.FALSE);

        ECPointFormatUncompressedOnlyCheck check =
                new ECPointFormatUncompressedOnlyCheck(null, null);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.ADHERED, result.getAdherence());
    }

    @Test
    public void testConditionNotMet() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS,
                Collections.singleton(ExtensionType.COOKIE));

        ECPointFormatUncompressedOnlyCheck check =
                new ECPointFormatUncompressedOnlyCheck(null, null);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.CONDITION_NOT_MET, result.getAdherence());
    }

    @Test
    public void testNegative() {
        // All compressed formats supported
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS,
                Collections.singleton(ExtensionType.EC_POINT_FORMATS));
        report.putResult(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, TestResults.TRUE);
        ECPointFormatUncompressedOnlyCheck check =
                new ECPointFormatUncompressedOnlyCheck(null, null);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());

        // Both uncompressed and ansiX962_compressed_char2 supported
        report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS,
                Collections.singleton(ExtensionType.EC_POINT_FORMATS));
        report.putResult(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, TestResults.FALSE);
        result = check.evaluate(report);
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());

        // Both uncompressed and ansiX962_compressed_prime supported
        report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS,
                Collections.singleton(ExtensionType.EC_POINT_FORMATS));
        report.putResult(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, TestResults.FALSE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, TestResults.TRUE);
        result = check.evaluate(report);
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());

        // Both ansiX962_compressed_char2 and ansiX962_compressed_prime supported
        report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS,
                Collections.singleton(ExtensionType.EC_POINT_FORMATS));
        report.putResult(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, TestResults.FALSE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, TestResults.TRUE);
        result = check.evaluate(report);
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());

        // Only ansiX962_compressed_char2 supported
        report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS,
                Collections.singleton(ExtensionType.EC_POINT_FORMATS));
        report.putResult(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, TestResults.FALSE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, TestResults.TRUE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, TestResults.FALSE);
        result = check.evaluate(report);
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());

        // Only ansiX962_compressed_prime supported
        report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS,
                Collections.singleton(ExtensionType.EC_POINT_FORMATS));
        report.putResult(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT, TestResults.FALSE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2, TestResults.FALSE);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME, TestResults.TRUE);
        result = check.evaluate(report);
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());
    }
}
