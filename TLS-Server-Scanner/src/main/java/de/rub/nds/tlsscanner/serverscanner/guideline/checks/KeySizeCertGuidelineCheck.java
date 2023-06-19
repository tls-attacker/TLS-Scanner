/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.KeySizeCertGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.KeySizeData;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Locale;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeySizeCertGuidelineCheck extends CertificateGuidelineCheck {

    private Integer minimumDsaKeyLength;
    private Integer minimumRsaKeyLength;
    private Integer minimumEcKeyLength;
    private Integer minimumDhKeyLength;

    private KeySizeCertGuidelineCheck() {
        super(null, null);
    }

    public KeySizeCertGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            Integer minimumDsaKeyLength,
            Integer minimumRsaKeyLength,
            Integer minimumEcKeyLength,
            Integer minimumDhKeyLength) {
        super(name, requirementLevel);
        this.minimumDsaKeyLength = minimumDsaKeyLength;
        this.minimumRsaKeyLength = minimumRsaKeyLength;
        this.minimumEcKeyLength = minimumEcKeyLength;
        this.minimumDhKeyLength = minimumDhKeyLength;
    }

    public KeySizeCertGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            boolean onlyOneCertificate,
            Integer minimumDsaKeyLength,
            Integer minimumRsaKeyLength,
            Integer minimumEcKeyLength,
            Integer minimumDhKeyLength) {
        super(name, requirementLevel, onlyOneCertificate);
        this.minimumDsaKeyLength = minimumDsaKeyLength;
        this.minimumRsaKeyLength = minimumRsaKeyLength;
        this.minimumEcKeyLength = minimumEcKeyLength;
        this.minimumDhKeyLength = minimumDhKeyLength;
    }

    public KeySizeCertGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean onlyOneCertificate,
            Integer minimumDsaKeyLength,
            Integer minimumRsaKeyLength,
            Integer minimumEcKeyLength,
            Integer minimumDhKeyLength) {
        super(name, requirementLevel, condition, onlyOneCertificate);
        this.minimumDsaKeyLength = minimumDsaKeyLength;
        this.minimumRsaKeyLength = minimumRsaKeyLength;
        this.minimumEcKeyLength = minimumEcKeyLength;
        this.minimumDhKeyLength = minimumDhKeyLength;
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChain chain) {
        boolean passFlag = false;
        boolean uncertainFlag = false;
        boolean failedFlag = false;
        KeySizeCertGuidelineCheckResult result = new KeySizeCertGuidelineCheckResult();
        for (CertificateReport report : chain.getCertificateReportList()) {
            if (!(report.getPublicKey() instanceof CustomPublicKey)) {
                uncertainFlag = true;
                continue;
            }
            CustomPublicKey key = (CustomPublicKey) report.getPublicKey();
            switch (report.getPublicKey().getAlgorithm().toUpperCase(Locale.ENGLISH)) {
                case "DSA":
                    if (this.minimumDsaKeyLength != null) {
                        result.addKeySize(
                                new KeySizeData(
                                        report.getPublicKey().getAlgorithm(),
                                        this.minimumDsaKeyLength,
                                        key.keySize()));
                        if (key.keySize() < this.minimumDsaKeyLength) {
                            failedFlag = true;
                        } else {
                            passFlag = true;
                        }
                    }
                    break;
                case "RSA":
                    if (this.minimumRsaKeyLength != null) {
                        result.addKeySize(
                                new KeySizeData(
                                        report.getPublicKey().getAlgorithm(),
                                        this.minimumRsaKeyLength,
                                        key.keySize()));
                        if (key.keySize() < this.minimumRsaKeyLength) {
                            failedFlag = true;
                        } else {
                            passFlag = true;
                        }
                    }

                    break;
                case "EC":
                    if (this.minimumEcKeyLength != null) {
                        result.addKeySize(
                                new KeySizeData(
                                        report.getPublicKey().getAlgorithm(),
                                        this.minimumEcKeyLength,
                                        key.keySize()));
                        if (key.keySize() < this.minimumEcKeyLength) {
                            failedFlag = true;
                        } else {
                            passFlag = true;
                        }
                    }
                    break;
                case "DH":
                    if (this.minimumDhKeyLength != null) {
                        result.addKeySize(
                                new KeySizeData(
                                        report.getPublicKey().getAlgorithm(),
                                        this.minimumDhKeyLength,
                                        key.keySize()));
                        if (key.keySize() < this.minimumDhKeyLength) {
                            failedFlag = true;
                        } else {
                            passFlag = true;
                        }
                    }
                    break;
            }
        }
        if (failedFlag) {
            result.setResult(TestResults.FALSE);
        } else if (uncertainFlag || !passFlag) {
            result.setResult(TestResults.UNCERTAIN);
        } else {
            result.setResult(TestResults.TRUE);
        }
        return result;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        if (report.getWeakestDhStrength() != null && this.minimumDhKeyLength != null) {
            if (report.getWeakestDhStrength() < this.minimumDhKeyLength) {
                return new GuidelineCheckResult(TestResults.FALSE) {
                    @Override
                    public String display() {
                        return String.format(
                                "Weakest DH size %d<%d",
                                report.getWeakestDhStrength(), minimumDhKeyLength);
                    }
                };
            }
        }
        return super.evaluate(report);
    }

    @Override
    public String getId() {
        return "KeySizeCert_"
                + getRequirementLevel()
                + "_"
                + minimumDsaKeyLength
                + "_"
                + minimumRsaKeyLength
                + "_"
                + minimumEcKeyLength
                + "_"
                + minimumDhKeyLength;
    }

    public Integer getMinimumDsaKeyLength() {
        return minimumDsaKeyLength;
    }

    public Integer getMinimumRsaKeyLength() {
        return minimumRsaKeyLength;
    }

    public Integer getMinimumEcKeyLength() {
        return minimumEcKeyLength;
    }

    public Integer getMinimumDhKeyLength() {
        return minimumDhKeyLength;
    }
}
