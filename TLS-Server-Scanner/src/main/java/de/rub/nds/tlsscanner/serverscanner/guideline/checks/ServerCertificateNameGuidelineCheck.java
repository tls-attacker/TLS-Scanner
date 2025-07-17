/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.checks;

import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckCondition;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.scanner.core.guideline.RequirementLevel;
import de.rub.nds.tlsscanner.core.guideline.checks.CertificateNameGuidelineCheck;
import de.rub.nds.tlsscanner.core.guideline.results.CertificateNameGuidelineCheckResult;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import de.rub.nds.x509attacker.constants.X500AttributeType;
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
 * having only one value per RDN, using only PrintableString characters and having the subject CN
 * match the hostname or IP of the server.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ServerCertificateNameGuidelineCheck extends CertificateNameGuidelineCheck {

    private ServerReport serverReport;

    private ServerCertificateNameGuidelineCheck() {
        super(null, null);
    }

    public ServerCertificateNameGuidelineCheck(String name, RequirementLevel requirementLevel) {
        super(name, requirementLevel);
    }

    public ServerCertificateNameGuidelineCheck(
            String name, RequirementLevel requirementLevel, boolean onlyOneCertificate) {
        super(name, requirementLevel, onlyOneCertificate);
    }

    public ServerCertificateNameGuidelineCheck(
            String name,
            RequirementLevel requirementLevel,
            GuidelineCheckCondition condition,
            boolean onlyOneCertificate) {
        super(name, requirementLevel, condition, onlyOneCertificate);
    }

    @Override
    public GuidelineCheckResult evaluate(TlsScanReport report) {
        if (report instanceof ServerReport) {
            serverReport = (ServerReport) report;
        }
        return super.evaluate(report);
    }

    @Override
    public GuidelineCheckResult evaluateChain(CertificateChainReport chain) {
        super.evaluateChain(chain);

        X509Certificate cert = chain.getLeafReport().getCertificate();
        Optional<RelativeDistinguishedName> cnRdn =
                cert.getTbsCertificate().getSubject().getRelativeDistinguishedNames().stream()
                        .filter(
                                rdn ->
                                        rdn.getAttributeTypeAndValueList()
                                                        .get(0)
                                                        .getX500AttributeTypeFromValue()
                                                == X500AttributeType.COMMON_NAME)
                        .findFirst();
        if (cnRdn.isPresent()) {
            String ip;
            try {
                ip = InetAddress.getByName(serverReport.getHost()).toString();
            } catch (UnknownHostException e) {
                // should not happen, since the host is used for the test
                throw new RuntimeException(
                        "Cannot get IP for unknown host " + serverReport.getHost(), e);
            }
            if (!List.of(ip, serverReport.getHost())
                    .contains(
                            cnRdn.get()
                                    .getAttributeTypeAndValueList()
                                    .getFirst()
                                    .getStringValueOfValue())) {
                return new CertificateNameGuidelineCheckResult(
                        getName(),
                        GuidelineAdherence.VIOLATED,
                        cnRdn.get().getIdentifier(),
                        "Common Name should be hostname or IP address.");
            }
        }

        return null;
    }
}
