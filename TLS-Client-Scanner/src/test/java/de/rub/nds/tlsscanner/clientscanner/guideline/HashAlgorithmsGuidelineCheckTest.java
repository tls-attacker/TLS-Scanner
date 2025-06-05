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
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.clientscanner.guideline.checks.HashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.Collections;
import org.junit.jupiter.api.Test;

public class HashAlgorithmsGuidelineCheckTest {

    @Test
    public void testPositive() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS,
                Collections.singletonList(SignatureAndHashAlgorithm.RSA_SHA1));
        HashAlgorithmsGuidelineCheck check =
                new HashAlgorithmsGuidelineCheck(
                        null,
                        null,
                        Collections.singletonList(
                                SignatureAndHashAlgorithm.RSA_SHA1.getHashAlgorithm()));
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.ADHERED, result.getAdherence());
    }

    @Test
    public void testNegative() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS,
                Collections.singletonList(SignatureAndHashAlgorithm.RSA_SHA224));
        HashAlgorithmsGuidelineCheck check =
                new HashAlgorithmsGuidelineCheck(
                        null,
                        null,
                        Collections.singletonList(
                                SignatureAndHashAlgorithm.RSA_SHA1.getHashAlgorithm()));
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());
    }

    public void testPositiveNotRecommended() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS,
                Collections.singletonList(SignatureAndHashAlgorithm.RSA_SHA224));
        HashAlgorithmsGuidelineCheck check =
                new HashAlgorithmsGuidelineCheck(
                        null,
                        null,
                        Collections.singletonList(
                                SignatureAndHashAlgorithm.RSA_SHA1.getHashAlgorithm()),
                        false);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.ADHERED, result.getAdherence());
    }

    @Test
    public void testNegativeNotRecommended() {
        ClientReport report = new ClientReport();
        report.putResult(
                TlsAnalyzedProperty.CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS,
                Collections.singletonList(SignatureAndHashAlgorithm.RSA_SHA1));
        HashAlgorithmsGuidelineCheck check =
                new HashAlgorithmsGuidelineCheck(
                        null,
                        null,
                        Collections.singletonList(
                                SignatureAndHashAlgorithm.RSA_SHA1.getHashAlgorithm()),
                        false);
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(GuidelineAdherence.VIOLATED, result.getAdherence());
    }
}
