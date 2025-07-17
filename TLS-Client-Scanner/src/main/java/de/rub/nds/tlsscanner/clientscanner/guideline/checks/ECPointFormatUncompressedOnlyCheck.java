/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline.checks;

import de.rub.nds.scanner.core.guideline.*;
import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.clientscanner.guideline.results.ECPointFormatUncompressedOnlyCheckResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.guideline.checks.TlsGuidelineCheck;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * Checks if the client only supports the uncompressed point format for EC.
 *
 * <p>CONDITION_NOT_MET: If the client does not use the ec_point_formats extension the check cannot
 * be performed.
 *
 * <p>VIOLATED: If any of these is true
 *
 * <p>1. The extension does not contain the uncompressed point format.
 *
 * <p>2. The extension does contain the ansiX962_compressed_prime format.
 *
 * <p>3. The extension does contain the ansiX962_compressed_char2 format.
 *
 * <p>ADHERED: If the extension only contains the uncompressed point format.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ECPointFormatUncompressedOnlyCheck extends TlsGuidelineCheck {

    private ECPointFormatUncompressedOnlyCheck() {
        super(null, null);
    }

    public ECPointFormatUncompressedOnlyCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public ECPointFormatUncompressedOnlyCheck(
            String name, RequirementLevel requirementLevel, GuidelineCheckCondition condition) {
        super(name, requirementLevel, condition);
    }

    @Override
    public GuidelineCheckResult evaluate(TlsScanReport tlsReport) {
        ClientReport clientReport;
        if (tlsReport instanceof ClientReport) {
            clientReport = (ClientReport) tlsReport;
        } else {
            return null;
        }
        // Step 1: Check if client uses ec_point_formats extension.
        if (!clientReport
                .getClientAdvertisedExtensions()
                .contains(ExtensionType.EC_POINT_FORMATS)) {
            return new ECPointFormatUncompressedOnlyCheckResult(
                    getName(), GuidelineAdherence.CONDITION_NOT_MET);
        }

        // Step 2: Check if TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT is not
        // TestResults.FALSE.
        TestResult supportsUncompressedPointResult =
                clientReport.getResult(TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT);
        switch ((TestResults) supportsUncompressedPointResult) {
            case UNCERTAIN:
            case COULD_NOT_TEST:
            case CANNOT_BE_TESTED:
            case ERROR_DURING_TEST:
            case NOT_TESTED_YET:
            case TIMEOUT:
                return new ECPointFormatUncompressedOnlyCheckResult(
                        getName(), GuidelineAdherence.CHECK_FAILED);
            case FALSE:
                return new ECPointFormatUncompressedOnlyCheckResult(
                        getName(), GuidelineAdherence.VIOLATED);
            default:
                break;
        }

        // Step 3: Check if both are not TestResults.TRUE:
        // TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME
        // TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2
        TestResult supportsAnsiX962CompressedPrimeResult =
                clientReport.getResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME);
        switch ((TestResults) supportsAnsiX962CompressedPrimeResult) {
            case UNCERTAIN:
            case COULD_NOT_TEST:
            case CANNOT_BE_TESTED:
            case ERROR_DURING_TEST:
            case NOT_TESTED_YET:
            case TIMEOUT:
                return new ECPointFormatUncompressedOnlyCheckResult(
                        getName(), GuidelineAdherence.CHECK_FAILED);
            case TRUE:
                return new ECPointFormatUncompressedOnlyCheckResult(
                        getName(), GuidelineAdherence.VIOLATED);
            default:
                break;
        }

        TestResult supportsAnsiX962CompressedChar2Result =
                clientReport.getResult(TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2);
        switch ((TestResults) supportsAnsiX962CompressedChar2Result) {
            case UNCERTAIN:
            case COULD_NOT_TEST:
            case CANNOT_BE_TESTED:
            case ERROR_DURING_TEST:
            case NOT_TESTED_YET:
            case TIMEOUT:
                return new ECPointFormatUncompressedOnlyCheckResult(
                        getName(), GuidelineAdherence.CHECK_FAILED);
            case TRUE:
                return new ECPointFormatUncompressedOnlyCheckResult(
                        getName(), GuidelineAdherence.VIOLATED);
            default:
                break;
        }

        // If the three condition above are met, the check it passed.
        return new ECPointFormatUncompressedOnlyCheckResult(getName(), GuidelineAdherence.ADHERED);
    }

    @Override
    public String toString() {
        return "ECPointFormatUncompressedOnlyCheck_" + getRequirementLevel();
    }
}
