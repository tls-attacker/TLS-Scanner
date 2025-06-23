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

    /** No-arg constructor for deserialization */
    @SuppressWarnings("unused")
    public CertificateChainReport() {
        certificateIssues = new LinkedList<>();
        certificateReportList = new LinkedList<>();
        platformsTrustingCertificate = new LinkedList<>();
        platformsNotTrustingCertificate = new LinkedList<>();
        platformsBlacklistingCertificate = new LinkedList<>();
        trustPaths = new LinkedList<>();
    }

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

    /**
     * Returns the certificate report for the leaf certificate in the chain.
     *
     * @return the leaf certificate report
     */
    public CertificateReport getLeafReport() {
        return leafReport;
    }

    /**
     * Sets the certificate report for the leaf certificate in the chain.
     *
     * @param leafReport the leaf certificate report to set
     */
    public void setLeafReport(CertificateReport leafReport) {
        this.leafReport = leafReport;
    }

    /**
     * Returns the list of trust paths found for this certificate chain.
     *
     * @return the list of trust paths
     */
    public List<TrustPath> getTrustPaths() {
        return trustPaths;
    }

    /**
     * Returns the list of certificate issues found in this certificate chain.
     *
     * @return the list of certificate issues
     */
    public List<CertificateIssue> getCertificateIssues() {
        return certificateIssues;
    }

    /**
     * Sets the list of certificate issues for this certificate chain.
     *
     * @param certificateIssues the list of certificate issues to set
     */
    public void setCertificateIssues(List<CertificateIssue> certificateIssues) {
        this.certificateIssues = certificateIssues;
    }

    /**
     * Returns whether the certificate chain contains any not-yet-valid certificates.
     *
     * @return true if the chain contains not-yet-valid certificates, false otherwise
     */
    public Boolean getContainsNotYetValid() {
        return containsNotYetValid;
    }

    /**
     * Sets whether the certificate chain contains any not-yet-valid certificates.
     *
     * @param containsNotYetValid true if the chain contains not-yet-valid certificates
     */
    public void setContainsNotYetValid(Boolean containsNotYetValid) {
        this.containsNotYetValid = containsNotYetValid;
    }

    /**
     * Returns whether the certificate chain contains any expired certificates.
     *
     * @return true if the chain contains expired certificates, false otherwise
     */
    public Boolean getContainsExpired() {
        return containsExpired;
    }

    /**
     * Sets whether the certificate chain contains any expired certificates.
     *
     * @param containsExpired true if the chain contains expired certificates
     */
    public void setContainsExpired(Boolean containsExpired) {
        this.containsExpired = containsExpired;
    }

    /**
     * Returns whether the chain contains weakly-signed certificates that are not in trust stores.
     *
     * @return true if the chain contains weakly-signed non-trust-store certificates
     */
    public Boolean getContainsWeakSignedNonTrustStoresCertificates() {
        return containsWeakSignedNonTrustStoresCertificates;
    }

    /**
     * Sets whether the chain contains weakly-signed certificates that are not in trust stores.
     *
     * @param containsWeakSignedNonTrustStoresCertificates true if the chain contains weakly-signed
     *     non-trust-store certificates
     */
    public void setContainsWeakSignedNonTrustStoresCertificates(
            Boolean containsWeakSignedNonTrustStoresCertificates) {
        this.containsWeakSignedNonTrustStoresCertificates =
                containsWeakSignedNonTrustStoresCertificates;
    }

    /**
     * Returns the certificate report for the trust anchor in the chain.
     *
     * @return the trust anchor certificate report
     */
    public CertificateReport getTrustAnchor() {
        return trustAnchor;
    }

    /**
     * Sets the certificate report for the trust anchor in the chain.
     *
     * @param trustAnchor the trust anchor certificate report to set
     */
    public void setTrustAnchor(CertificateReport trustAnchor) {
        this.trustAnchor = trustAnchor;
    }

    /**
     * Returns whether the certificate chain is generally trusted.
     *
     * @return true if the chain is generally trusted, false otherwise
     */
    public Boolean getGenerallyTrusted() {
        return generallyTrusted;
    }

    /**
     * Returns whether the certificate chain contains a trust anchor.
     *
     * @return true if the chain contains a trust anchor, false otherwise
     */
    public Boolean getContainsTrustAnchor() {
        return containsTrustAnchor;
    }

    /**
     * Returns whether the certificate chain is complete.
     *
     * @return true if the chain is complete, false otherwise
     */
    public Boolean getChainIsComplete() {
        return chainIsComplete;
    }

    /**
     * Returns whether the certificate chain is properly ordered.
     *
     * @return true if the chain is ordered correctly, false otherwise
     */
    public Boolean getChainIsOrdered() {
        return chainIsOrdered;
    }

    /**
     * Returns whether the certificate chain contains multiple leaf certificates.
     *
     * @return true if the chain contains multiple leaves, false otherwise
     */
    public Boolean getContainsMultipleLeaves() {
        return containsMultipleLeaves;
    }

    /**
     * Returns whether the certificate chain contains a valid leaf certificate.
     *
     * @return true if the chain contains a valid leaf, false otherwise
     */
    public Boolean getContainsValidLeaf() {
        return containsValidLeaf;
    }

    /**
     * Returns the list of platforms that trust this certificate chain.
     *
     * @return the list of trusting platforms
     */
    public List<TrustPlatform> getPlatformsTrustingCertificate() {
        return platformsTrustingCertificate;
    }

    /**
     * Returns the list of platforms that do not trust this certificate chain.
     *
     * @return the list of non-trusting platforms
     */
    public List<TrustPlatform> getPlatformsNotTrustingCertificate() {
        return platformsNotTrustingCertificate;
    }

    /**
     * Returns the list of platforms that have blacklisted this certificate chain.
     *
     * @return the list of blacklisting platforms
     */
    public List<TrustPlatform> getPlatformsBlacklistingCertificate() {
        return platformsBlacklistingCertificate;
    }

    /**
     * Returns the list of certificate reports for all certificates in the chain.
     *
     * @return the list of certificate reports
     */
    public List<CertificateReport> getCertificateReportList() {
        return certificateReportList;
    }

    /**
     * Returns whether the certificate chain contains a custom trust anchor.
     *
     * @return true if the chain contains a custom trust anchor, false otherwise
     */
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
