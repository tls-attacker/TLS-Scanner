/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.tlsscanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.KeySizeCertGuidelineCheckResult;
import de.rub.nds.tlsscanner.serverscanner.guideline.results.KeySizeData;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

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
    public GuidelineCheckResult evaluateChain(CertificateChainReport chain) {
        boolean passFlag = false;
        boolean uncertainFlag = false;
        boolean failedFlag = false;
        KeySizeCertGuidelineCheckResult result = new KeySizeCertGuidelineCheckResult(getName());
        for (CertificateReport report : chain.getCertificateReportList()) {
            
            PublicKeyContainer key = report.getPublicKey();
            int keySize = key.length();
            Integer minimumKeySize = null;
            String algoName = null;
            if(key instanceof DsaPublicKey)
            {
                algoName = "DSA";
                minimumKeySize = this.minimumDsaKeyLength;
            } else if(key instanceof RsaPublicKey)
            {
                algoName = "RSA";
                minimumKeySize = this.minimumRsaKeyLength;    
            } else if(key instanceof EcdhPublicKey || key instanceof EcdsaPublicKey)
            {
                algoName = "EC";
                minimumKeySize = this.minimumEcKeyLength;    
            }else if(key instanceof DhPublicKey)
            {
                algoName = "DH";
                minimumKeySize = this.minimumDhKeyLength;    
            } 
            if(minimumKeySize != null)
            {
                result.addKeySize(
                                new KeySizeData(
                                        algoName,
                                        minimumKeySize,
                                        keySize));
                        if (key.length() < minimumKeySize) {
                            failedFlag = true;
                        } else {
                            passFlag = true;
                        }
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
            result.setAdherence(GuidelineAdherence.VIOLATED);
        } else if (uncertainFlag || !passFlag) {
            result.setAdherence(GuidelineAdherence.CHECK_FAILED);
        } else {
            result.setAdherence(GuidelineAdherence.ADHERED);
        }
        }
        return result;
    }

    @Override
    public GuidelineCheckResult evaluate(ServerReport report) {
        if (report.getWeakestDhStrength() != null && this.minimumDhKeyLength != null) {
            if (report.getWeakestDhStrength() < this.minimumDhKeyLength) {
                return new GuidelineCheckResult(getName(), GuidelineAdherence.VIOLATED) {
                    @Override
                    public String toString() {
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
    public String toString() {
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
