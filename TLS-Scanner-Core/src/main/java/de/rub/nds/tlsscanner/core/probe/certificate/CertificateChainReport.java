/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.certificate;

import de.rub.nds.tlsscanner.core.trust.TrustPlatform;
import de.rub.nds.x509attacker.trust.TrustPath;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Note: Please do not copy from this code - (or any other certificate related code (or any TLS
 * code)). This code is not meant for productive usage and is very very likely doing things which
 * are terribly bad in any real system. This code is only built for security analysis purposes. Do
 * not use it for anything but this!
 */
public class CertificateChainReport {

    private static final Logger LOGGER = LogManager.getLogger();

    private Boolean generallyTrusted = null;

    private Boolean containsCustomTrustAnchor = null;

    private Boolean containsTrustAnchor = null;

    private Boolean chainIsComplete = null;

    private Boolean chainIsOrdered = null;

    private Boolean containsMultipleLeaves = null;

    private Boolean containsValidLeaf = null;

    private Boolean containsNotYetValid = null;

    private Boolean containsExpired = null;

    private Boolean containsWeakSignedNonTrustStoresCertificates;

    private List<TrustPlatform> platformsTrustingCertificate;

    private List<TrustPlatform> platformsNotTrustingCertificate;

    private List<TrustPlatform> platformsBlacklistingCertificate;

    private List<CertificateReport> certificateReportList;

    private CertificateReport trustAnchor;

    private CertificateReport leafReport;

    private List<CertificateIssue> certificateIssues;

    private List<TrustPath> trustPaths;

    /** Private no-arg constructor to please JAXB */
    @SuppressWarnings("unused")
    private CertificateChainReport() {}

    public CertificateChainReport(X509CertificateChain certificateChain, String uri) {
        certificateIssues = new LinkedList<>();
        certificateReportList = new LinkedList<>();
        for (X509Certificate cert : certificateChain.getCertificateList()) {
            CertificateReport certificateReport = CertificateReportGenerator.generateReport(cert);
            certificateReportList.add(certificateReport);
        }
        LOGGER.debug("Certificate Reports:" + certificateReportList.size());
        // Check if trust anchor or custom trust anchor is contained
        containsTrustAnchor = false;
        containsCustomTrustAnchor = false;
        for (CertificateReport report : certificateReportList) {
            if (Objects.equals(report.isTrustAnchor(), Boolean.TRUE)) {
                containsTrustAnchor = true;
            }

            if (Objects.equals(report.isCustomTrustAnchor(), Boolean.TRUE)) {
                containsCustomTrustAnchor = true;
            }
        }
        // find leaf certificate
        containsMultipleLeaves = certificateChain.containsMultipleLeafs();
        containsValidLeaf = certificateChain.containsValidLeaf(uri);
        chainIsOrdered = true; // TODO certificateChain.isChainOrdered();

        chainIsComplete = true; // TODO

        containsNotYetValid = certificateChain.containsNotYetValidCertificate();
        containsExpired = certificateChain.containsExpiredCertificate();
        containsWeakSignedNonTrustStoresCertificates = null; // TODO
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

        trustPaths = certificateChain.getAllTrustPaths(null); // TODO add trust anchors
        // TODO This is a weaker form of "generally trusted" which we had before as it only
        // validates that there is a trust path
        // we also need to validate that the trust path is correctly signed and that extensions are
        // met.
    }

    public CertificateReport getLeafReport() {
        return leafReport;
    }

    public void setLeafReport(CertificateReport leafReport) {
        this.leafReport = leafReport;
    }

    public List<TrustPath> getTrustPaths() {
        return trustPaths;
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

    public void setContainsWeakSignedNonTrustStoresCertificates(
            Boolean containsWeakSignedNonTrustStoresCertificates) {
        this.containsWeakSignedNonTrustStoresCertificates =
                containsWeakSignedNonTrustStoresCertificates;
    }

    public CertificateReport getTrustAnchor() {
        return trustAnchor;
    }

    public void setTrustAnchor(CertificateReport trustAnchor) {
        this.trustAnchor = trustAnchor;
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

    public Boolean getContainsCustomTrustAnchor() {
        return containsCustomTrustAnchor;
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
        final CertificateChainReport otherCert = (CertificateChainReport) obj;
        if (certificateReportList.size() != otherCert.getCertificateReportList().size()
                || !Objects.equals(generallyTrusted, otherCert.getGenerallyTrusted())
                || !Objects.equals(containsTrustAnchor, otherCert.getContainsTrustAnchor())
                || !Objects.equals(chainIsComplete, otherCert.getChainIsComplete())
                || !Objects.equals(chainIsOrdered, otherCert.getChainIsOrdered())
                || !Objects.equals(containsMultipleLeaves, otherCert.getContainsMultipleLeaves())
                || !Objects.equals(containsValidLeaf, otherCert.getContainsValidLeaf())
                || !Objects.equals(containsNotYetValid, otherCert.getContainsNotYetValid())
                || !Objects.equals(containsExpired, otherCert.getContainsExpired())
                || !Objects.equals(
                        containsWeakSignedNonTrustStoresCertificates,
                        otherCert.getContainsWeakSignedNonTrustStoresCertificates())) {
            return false;
        } else {
            for (int i = 0; i < certificateReportList.size(); i++) {
                if (!certificateReportList
                        .get(i)
                        .equals(otherCert.getCertificateReportList().get(i))) {
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
