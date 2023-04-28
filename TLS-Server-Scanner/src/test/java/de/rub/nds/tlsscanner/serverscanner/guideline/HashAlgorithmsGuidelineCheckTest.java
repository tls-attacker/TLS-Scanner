/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

import org.junit.jupiter.api.Test;

import java.util.Collections;

public class HashAlgorithmsGuidelineCheckTest {

    @Test
    public void testPositive() {
        ServerReport report = new ServerReport("test", 443);
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE,
                new ListResult<>(
                        Collections.singletonList(SignatureAndHashAlgorithm.RSA_SHA1),
                        "SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE"));
        HashAlgorithmsGuidelineCheck check =
                new HashAlgorithmsGuidelineCheck(
                        null,
                        null,
                        Collections.singletonList(
                                SignatureAndHashAlgorithm.RSA_SHA1.getHashAlgorithm()));
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(TestResults.TRUE, result.getResult());
    }

    @Test
    public void testNegative() {
        ServerReport report = new ServerReport("test", 443);
        report.putResult(
                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE,
                new ListResult<>(
                        Collections.singletonList(SignatureAndHashAlgorithm.RSA_SHA224),
                        "SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE"));
        HashAlgorithmsGuidelineCheck check =
                new HashAlgorithmsGuidelineCheck(
                        null,
                        null,
                        Collections.singletonList(
                                SignatureAndHashAlgorithm.RSA_SHA1.getHashAlgorithm()));
        GuidelineCheckResult result = check.evaluate(report);
        assertEquals(TestResults.FALSE, result.getResult());
    }
}
