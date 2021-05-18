/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.certificate;

import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.trust.TrustAnchorManager;
import de.rub.nds.tlsscanner.serverscanner.trust.TrustPlatform;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.path.CertPath;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationException;
import org.bouncycastle.cert.path.CertPathValidationResult;
import org.bouncycastle.cert.path.validations.BasicConstraintsValidation;
import org.bouncycastle.cert.path.validations.KeyUsageValidation;
import org.bouncycastle.cert.path.validations.ParentCertIssuedValidation;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.util.HostnameChecker;

/**
 * Note: Please do not copy from this code - (or any other certificate related code (or any TLS code)). This code is not
 * meant for productive usage and is very very likely doing things which are terribly bad in any real system. This code
 * is only built for security analysis purposes. Do not use it for anything but this!
 *
 * @author ic0ns
 */
public class CertificateChain {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Certificate certificate;

    private Boolean generallyTrusted = null;

    private Boolean containsTrustAnchor = null;

    private Boolean chainIsComplete = null;

    private Boolean chainIsOrdered = null;

    private Boolean containsMultipleLeaves = null;

    private Boolean containsValidLeaf = null;

    private Boolean containsNotYetValid;

    private Boolean containsExpired;

    private Boolean containsWeakSignedNonTrustStoresCertificates;

    private List<TrustPlatform> platformsTrustingCertificate;

    private List<TrustPlatform> platformsNotTrustingCertificate;

    private List<TrustPlatform> platformsBlacklistingCertificate;

    private List<CertificateReport> certificateReportList;

    private CertificateReport trustAnchor;

    private List<CertificateIssue> certificateIssues;

    private CertificateChain() {
        certificate = null;
    }

    public CertificateChain(Certificate certificate, String uri) {
        certificateIssues = new LinkedList<>();
        List<CertificateReport> orderedCertificateChain = new LinkedList<>();
        this.certificate = certificate;
        certificateReportList = new LinkedList<>();
        for (org.bouncycastle.asn1.x509.Certificate cert : certificate.getCertificateList()) {
            CertificateReport certificateReport = CertificateReportGenerator.generateReport(cert);
            certificateReportList.add(certificateReport);
        }
        LOGGER.debug("Certificate Reports:" + certificateReportList.size());
        // Check if trust anchor is contained
        containsTrustAnchor = false;
        for (CertificateReport report : certificateReportList) {
            if (Objects.equals(report.isTrustAnchor(), Boolean.TRUE)) {
                containsTrustAnchor = true;
            }
        }
        // find leaf certificate
        CertificateReport leafReport = null;
        for (CertificateReport report : certificateReportList) {
            if (isCertificateSuitableForHost(report.convertToX509Certificate(), uri)) {
                report.setLeafCertificate(true);
                if (leafReport == null) {
                    leafReport = report;
                } else {
                    containsMultipleLeaves = true;
                }
            }
        }
        if (containsMultipleLeaves == null) {
            containsMultipleLeaves = false;
        }
        containsValidLeaf = leafReport != null;

        if (leafReport != null) {
            if (certificateReportList.isEmpty()
                || !certificateReportList.get(0).getSHA256Fingerprint().equals(leafReport.getSHA256Fingerprint())) {
                chainIsOrdered = false;
            } else {
                chainIsOrdered = checkCertificateChainIsOrdered(certificateReportList);
            }
            // Try to build a chain
            CertificateReport tempCertificate = leafReport;

            orderedCertificateChain.add(tempCertificate);
            while (!tempCertificate.getIssuer().equals(tempCertificate.getSubject())) {
                CertificateReport foundReport = null;
                for (CertificateReport report : certificateReportList) {
                    if (report.getSubject().equals(tempCertificate.getIssuer())) {
                        foundReport = report;
                    }
                }
                if (foundReport != null) {
                    LOGGER.debug("Found next certificate");
                    orderedCertificateChain.add(foundReport);
                    tempCertificate = foundReport;
                } else {
                    LOGGER.debug("Could not find next certificate");
                    // Could not find issuer for certificate - check if its in
                    // the trust store
                    if (TrustAnchorManager.getInstance().isInitialized()) {
                        if (TrustAnchorManager.getInstance()
                            .isTrustAnchor(tempCertificate.convertToX509Certificate().getIssuerX500Principal())) {
                            // Certificate is issued by trust anchor
                            LOGGER.debug("Could find issuer");
                            chainIsComplete = true;
                            org.bouncycastle.asn1.x509.Certificate trustAnchorCertificate =
                                TrustAnchorManager.getInstance().getTrustAnchorCertificate(
                                    tempCertificate.convertToX509Certificate().getIssuerX500Principal());
                            if (trustAnchorCertificate != null) {
                                CertificateReport trustAnchorReport =
                                    CertificateReportGenerator.generateReport(trustAnchorCertificate);
                                orderedCertificateChain.add(trustAnchorReport);
                                trustAnchorReport.setTrustAnchor(true);
                                trustAnchor = trustAnchorReport;
                            }
                        } else {
                            LOGGER.debug("Could not find issuer");
                            chainIsComplete = false;
                        }
                    } else {
                        LOGGER.error(
                            "Cannot check if the chain is complete since the trust manager is not " + "initialized");
                    }
                    break;
                }
            }
        } else {
            chainIsOrdered = true; // there is no leaf certificate - so i guess
            // this is ordered?
            containsValidLeaf = false;
        }
        containsNotYetValid = false;
        containsExpired = false;
        containsWeakSignedNonTrustStoresCertificates = false;
        for (CertificateReport report : certificateReportList) {
            if (report.getValidFrom().after(new Date())) {
                containsNotYetValid = true;
            }
            if (report.getValidTo().before(new Date())) {
                containsExpired = true;
            }
            if (Objects.equals(report.isTrustAnchor(), Boolean.FALSE)
                && Objects.equals(report.getSelfSigned(), Boolean.FALSE)
                && report.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.MD5
                || report.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.SHA1) {
                containsWeakSignedNonTrustStoresCertificates = true;
            }
        }
        for (CertificateReport report : certificateReportList) {
            if (Objects.equals(report.isTrustAnchor(), Boolean.FALSE)
                && Objects.equals(report.getSelfSigned(), Boolean.TRUE)
                && Objects.equals(report.getLeafCertificate(), Boolean.TRUE)) {
                certificateIssues.add(CertificateIssue.SELF_SIGNED);
                break;
            }
        }
        if (Objects.equals(chainIsComplete, Boolean.FALSE)) {
            certificateIssues.add(CertificateIssue.CHAIN_NOT_COMPLETE);
        }
        if (Objects.equals(containsValidLeaf, Boolean.FALSE)) {
            certificateIssues.add(CertificateIssue.COMMON_NAME_MISMATCH);
        }
        if (Objects.equals(containsExpired, Boolean.TRUE)) {
            certificateIssues.add(CertificateIssue.CHAIN_CONTAINS_EXPIRED);
        }
        if (Objects.equals(containsNotYetValid, Boolean.TRUE)) {
            certificateIssues.add(CertificateIssue.CHAIN_CONTAINS_NOT_YET_VALID);
        }
        if (Objects.equals(containsMultipleLeaves, Boolean.TRUE)) {
            certificateIssues.add(CertificateIssue.MULTIPLE_LEAVES);
        }
        if (Objects.equals(containsWeakSignedNonTrustStoresCertificates, Boolean.TRUE)) {
            certificateIssues.add(CertificateIssue.WEAK_SIGNATURE_OR_HASH_ALGORITHM);
        }
        if (Objects.equals(chainIsComplete, Boolean.TRUE) && Objects.equals(containsValidLeaf, Boolean.TRUE)
            && Objects.equals(containsExpired, Boolean.FALSE) && Objects.equals(containsNotYetValid, Boolean.FALSE)) {
            CertPathValidationResult certPathValidationResult = evaluateGeneralTrust(orderedCertificateChain);
            generallyTrusted = certPathValidationResult.isValid();
            if (!generallyTrusted) {
                CertPathValidationException[] causes = certPathValidationResult.getCauses();
                if (causes != null) {
                    for (CertPathValidationException exception : causes) {
                        if (exception.getCause().getMessage().contains("Unhandled Critical Extensions")) {
                            certificateIssues.add(CertificateIssue.UNHANDLED_CRITICAL_EXTENSIONS);
                        } else {
                            LOGGER.error("Unknown path validation issue", exception);
                        }
                    }
                }
            }
        } else {
            generallyTrusted = false;
        }

    }

    public List<CertificateIssue> getCertificateIssues() {
        return certificateIssues;
    }

    public void setCertificateIssues(List<CertificateIssue> certificateIssues) {
        this.certificateIssues = certificateIssues;
    }

    public Boolean getContainsNotYetValid() {
        return containsNotYetValid;
    }

    public void setContainsNotYetValid(Boolean containsNotYetValid) {
        this.containsNotYetValid = containsNotYetValid;
    }

    public Boolean getContainsExpired() {
        return containsExpired;
    }

    public void setContainsExpired(Boolean containsExpired) {
        this.containsExpired = containsExpired;
    }

    public Boolean getContainsWeakSignedNonTrustStoresCertificates() {
        return containsWeakSignedNonTrustStoresCertificates;
    }

    public void setContainsWeakSignedNonTrustStoresCertificates(Boolean containsWeakSignedNonTrustStoresCertificates) {
        this.containsWeakSignedNonTrustStoresCertificates = containsWeakSignedNonTrustStoresCertificates;
    }

    public CertificateReport getTrustAnchor() {
        return trustAnchor;
    }

    public void setTrustAnchor(CertificateReport trustAnchor) {
        this.trustAnchor = trustAnchor;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public Boolean getGenerallyTrusted() {
        return generallyTrusted;
    }

    public Boolean getContainsTrustAnchor() {
        return containsTrustAnchor;
    }

    public Boolean getChainIsComplete() {
        return chainIsComplete;
    }

    public Boolean getChainIsOrdered() {
        return chainIsOrdered;
    }

    public Boolean getContainsMultipleLeaves() {
        return containsMultipleLeaves;
    }

    public Boolean getContainsValidLeaf() {
        return containsValidLeaf;
    }

    public List<TrustPlatform> getPlatformsTrustingCertificate() {
        return platformsTrustingCertificate;
    }

    public List<TrustPlatform> getPlatformsNotTrustingCertificate() {
        return platformsNotTrustingCertificate;
    }

    public List<TrustPlatform> getPlatformsBlacklistingCertificate() {
        return platformsBlacklistingCertificate;
    }

    public List<CertificateReport> getCertificateReportList() {
        return certificateReportList;
    }

    public final boolean checkCertificateChainIsOrdered(List<CertificateReport> reports) {
        if (reports.isEmpty()) {
            return true; // i guess ^^
        } else {
            CertificateReport currentReport = reports.get(0);
            for (int i = 1; i < reports.size(); i++) {
                if (!reports.get(i).getSubject().equals(currentReport.getIssuer())) {
                    return false;
                } else {
                    currentReport = reports.get(i);
                }
            }
            return true;
        }
    }

    public final boolean isCertificateSuitableForHost(X509Certificate cert, String host) {
        HostnameChecker checker = HostnameChecker.getInstance(HostnameChecker.TYPE_TLS);
        try {
            checker.match(host, cert);
            return true;
        } catch (CertificateException ex) {
            LOGGER.debug("Cert is not valid for " + host + ":" + host);
            return false;
        }
    }

    private CertPathValidationResult evaluateGeneralTrust(List<CertificateReport> orderedCertificateChain) {
        if (orderedCertificateChain.size() < 2) {
            return null; // Emtpy chains & only root ca's are not considered
            // generally trusted i guess
        }
        X509CertificateHolder[] certPath = new X509CertificateHolder[orderedCertificateChain.size()];
        for (int i = 0; i < orderedCertificateChain.size(); i++) {
            certPath[i] = new X509CertificateHolder(orderedCertificateChain.get(i).getCertificate());
        }
        CertPath path = new CertPath(certPath);
        X509ContentVerifierProviderBuilder verifier =
            new JcaX509ContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
        CertPathValidationResult result = path.validate(new CertPathValidation[] {
            new ParentCertIssuedValidation(verifier), new BasicConstraintsValidation(), new KeyUsageValidation() });

        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CertificateChain otherCert = (CertificateChain) obj;
        if (certificateReportList.size() != otherCert.getCertificateReportList().size()
            || !Objects.equals(generallyTrusted, otherCert.getGenerallyTrusted())
            || !Objects.equals(containsTrustAnchor, otherCert.getContainsTrustAnchor())
            || !Objects.equals(chainIsComplete, otherCert.getChainIsComplete())
            || !Objects.equals(chainIsOrdered, otherCert.getChainIsOrdered())
            || !Objects.equals(containsMultipleLeaves, otherCert.getContainsMultipleLeaves())
            || !Objects.equals(containsValidLeaf, otherCert.getContainsValidLeaf())
            || !Objects.equals(containsNotYetValid, otherCert.getContainsNotYetValid())
            || !Objects.equals(containsExpired, otherCert.getContainsExpired())
            || !Objects.equals(containsWeakSignedNonTrustStoresCertificates,
                otherCert.getContainsWeakSignedNonTrustStoresCertificates())) {
            return false;
        } else {
            for (int i = 0; i < certificateReportList.size(); i++) {
                if (!certificateReportList.get(i).equals(otherCert.getCertificateReportList().get(i))) {
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    public int hashCode() {
        int hash = 5;
        hash = 29 * hash + Objects.hashCode(this.generallyTrusted);
        hash = 29 * hash + Objects.hashCode(this.containsTrustAnchor);
        hash = 29 * hash + Objects.hashCode(this.chainIsComplete);
        hash = 29 * hash + Objects.hashCode(this.chainIsOrdered);
        hash = 29 * hash + Objects.hashCode(this.containsMultipleLeaves);
        hash = 29 * hash + Objects.hashCode(this.containsValidLeaf);
        hash = 29 * hash + Objects.hashCode(this.containsNotYetValid);
        hash = 29 * hash + Objects.hashCode(this.containsExpired);
        hash = 29 * hash + Objects.hashCode(this.containsWeakSignedNonTrustStoresCertificates);
        hash = 29 * hash + Objects.hashCode(this.certificateReportList);
        hash = 29 * hash + Objects.hashCode(this.trustAnchor);
        hash = 29 * hash + Objects.hashCode(this.certificateIssues);
        return hash;
    }
}
