/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.clientscanner.guideline.checks;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.clientscanner.guideline.results.CertificateNameGuidelineCheckResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Optional;

/**
 * Checks the certificate issuer and subject for coherence to the NIST SP 800-52r2. This means,
 * having only one value per RDN, using only PrintableString characters.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateNameGuidelineCheck extends CertificateGuidelineCheck {

    private ClientReport clientReport;

    private CertificateNameGuidelineCheck() {
        super(null, null);
    }

    public CertificateNameGuidelineCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public CertificateNameGuidelineCheck(
            String name, RequirementLevel requirementLevel, boolean onlyOneCertificate) {
        super(name, requirementLevel, onlyOneCertificate);
    }

    public CertificateNameGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean onlyOneCertificate) {
        super(name, requirementLevel, condition, onlyOneCertificate);
    }

    public static boolean isPrintableString(String str) {
        if (str == null || str.isEmpty()) {
            return false; // Null or empty strings are not valid
        }

        // Define the regex pattern for PrintableString
        String printableStringPattern = "^[A-Za-z0-9 $'()+,-./:;]*$";

        return str.matches(printableStringPattern);
    }

    @Override
    public GuidelineCheckResult evaluate(ClientReport report) {
        this.clientReport = report;
        return super.evaluate(report);
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChainReport chain) {
        X509Certificate cert = chain.getLeafReport().getCertificate();
        for (Name name :
                List.of(
                        cert.getTbsCertificate().getIssuer(),
                        cert.getTbsCertificate().getSubject())) {
            for (RelativeDistinguishedName rdn : name.getRelativeDistinguishedNames()) {
                if (rdn.getAttributeTypeAndValueList().size() > 1) {
                    return new CertificateNameGuidelineCheckResult(
                            getName(),
                            GuidelineAdherence.VIOLATED,
                            rdn.toString(),
                            "More than one value in the RDN.");
                }
                if (isPrintableString(
                        rdn.getAttributeTypeAndValueList().get(0).getStringValueOfValue())) {
                    return new CertificateNameGuidelineCheckResult(
                            getName(),
                            GuidelineAdherence.VIOLATED,
                            rdn.toString(),
                            "Value is not a PrintableString.");
                }
            }
        }
        Optional<RelativeDistinguishedName> cnRdn =
                cert.getTbsCertificate().getSubject().getRelativeDistinguishedNames().stream()
                        .filter(
                                rdn ->
                                        rdn.getAttributeTypeAndValueList()
                                                .get(0)
                                                .getX500AttributeTypeFromValue()
                                                == X500AttributeType.COMMON_NAME)
                        .findFirst();
        // Removed check here when copying this class from serverscanner, because the NIST guide only requires this for servers: "If present, the CN attribute should be of the form: CN={host IP address | host DNS name}"
        return null;
    }

    @Override
    public String toString() {
        return "CertificateName_" + getRequirementLevel();
    }
}
