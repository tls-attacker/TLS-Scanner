/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline;

import de.rub.nds.tlsscanner.core.guideline.GuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.AnalyzedPropertyGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateAgilityGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateCurveGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateSignatureCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateValidityGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CertificateVersionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.CipherSuiteGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtendedKeyUsageCertificateCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.ExtensionGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmStrengthCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.HashAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.KeySizeCertGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.KeyUsageCertificateCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.NamedGroupsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAlgorithmsCertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAlgorithmsGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAndHashAlgorithmsCertificateGuidelineCheck;
import de.rub.nds.tlsscanner.serverscanner.guideline.checks.SignatureAndHashAlgorithmsGuidelineCheck;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElements;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlType;

import java.io.Serializable;
import java.util.List;

@XmlRootElement(name = "guideline")
@XmlType(propOrder = {"name", "link", "checks"})
@XmlAccessorType(XmlAccessType.FIELD)
public class Guideline implements Serializable {

    private String name;
    private String link;

    @XmlElements(
            value = {
                @XmlElement(
                        type = AnalyzedPropertyGuidelineCheck.class,
                        name = "AnalyzedPropertyGuidelineCheck"),
                @XmlElement(
                        type = CertificateCurveGuidelineCheck.class,
                        name = "CertificateCurveGuidelineCheck"),
                @XmlElement(
                        type = CertificateGuidelineCheck.class,
                        name = "CertificateGuidelineCheck"),
                @XmlElement(
                        type = CertificateSignatureCheck.class,
                        name = "CertificateSignatureCheck"),
                @XmlElement(
                        type = CertificateValidityGuidelineCheck.class,
                        name = "CertificateValidityGuidelineCheck"),
                @XmlElement(
                        type = CertificateVersionGuidelineCheck.class,
                        name = "CertificateVersionGuidelineCheck"),
                @XmlElement(
                        type = CipherSuiteGuidelineCheck.class,
                        name = "CipherSuiteGuidelineCheck"),
                @XmlElement(
                        type = ExtendedKeyUsageCertificateCheck.class,
                        name = "ExtendedKeyUsageCertificateCheck"),
                @XmlElement(type = ExtensionGuidelineCheck.class, name = "ExtensionGuidelineCheck"),
                @XmlElement(
                        type = HashAlgorithmStrengthCheck.class,
                        name = "HashAlgorithmStrengthCheck"),
                @XmlElement(
                        type = HashAlgorithmsGuidelineCheck.class,
                        name = "HashAlgorithmsGuidelineCheck"),
                @XmlElement(
                        type = KeySizeCertGuidelineCheck.class,
                        name = "KeySizeCertGuidelineCheck"),
                @XmlElement(
                        type = KeyUsageCertificateCheck.class,
                        name = "KeyUsageCertificateCheck"),
                @XmlElement(
                        type = NamedGroupsGuidelineCheck.class,
                        name = "NamedGroupsGuidelineCheck"),
                @XmlElement(
                        type = SignatureAlgorithmsCertificateGuidelineCheck.class,
                        name = "SignatureAlgorithmsCertificateGuidelineCheck"),
                @XmlElement(
                        type = SignatureAlgorithmsGuidelineCheck.class,
                        name = "SignatureAlgorithmsGuidelineCheck"),
                @XmlElement(
                        type = SignatureAndHashAlgorithmsCertificateGuidelineCheck.class,
                        name = "SignatureAndHashAlgorithmsCertificateGuidelineCheck"),
                @XmlElement(
                        type = SignatureAndHashAlgorithmsGuidelineCheck.class,
                        name = "SignatureAndHashAlgorithmsGuidelineCheck"),
                @XmlElement(
                        type = CertificateAgilityGuidelineCheck.class,
                        name = "CertificateAgilityGuidelineCheck"),
            })
    private List<GuidelineCheck> checks;

    private Guideline() {}

    public Guideline(String name, String link, List<GuidelineCheck> checks) {
        this.name = name;
        this.link = link;
        this.checks = checks;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLink() {
        return link;
    }

    public void setLink(String link) {
        this.link = link;
    }

    public List<GuidelineCheck> getChecks() {
        return checks;
    }

    public void setChecks(List<GuidelineCheck> checks) {
        this.checks = checks;
    }
}
