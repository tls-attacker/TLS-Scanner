/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.certificate;

import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsscanner.trust.TrustAnchorManager;
import de.rub.nds.tlsscanner.trust.TrustPlatform;
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
 * Note: Please do not copy from this code - (or any other certificate related
 * code (or any TLS code)). This code is not meant for productive usage and is
 * very very likely doing things which are terribly bad in any real system. This
 * code is only built for security analysis purposes. Do not use it for anything
 * but this!
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

    private Boolean containsMultipleLeafs = null;

    private Boolean containsValidLeaf = null;

    private Boolean containsNotYetValid;

    private Boolean containsExpired;

    private Boolean containsWeakSignedNonTruststoresCertificates;

    private List<TrustPlatform> platformsTrustingCertificate;

    private List<TrustPlatform> platformsNotTrustingCertificate;

    private List<TrustPlatform> platformsBlacklistingCertificate;

    private List<CertificateReport> certificateReportList;

    private CertificateReport trustAnchor;

    private List<CertificateIssue> certificateIssues;

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
        //Check if trust anchor is contained
        containsTrustAnchor = false;
        for (CertificateReport report : certificateReportList) {
            if (Objects.equals(report.isTrustAnchor(), Boolean.TRUE)) {
                containsTrustAnchor = true;
            }
        }
        //find leaf certificate
        CertificateReport leafReport = null;
        for (CertificateReport report : certificateReportList) {
            if (isCertificateSuiteableForHost(report.getX509Certificate(), uri)) {
                report.setLeafCertificate(true);
                if (leafReport == null) {
                    leafReport = report;
                } else {
                    containsMultipleLeafs = true;
                }
            }
        }
        if (containsMultipleLeafs == null) {
            containsMultipleLeafs = false;
        }
        containsValidLeaf = leafReport != null;

        if (leafReport != null) {
            if (certificateReportList.isEmpty() || !certificateReportList.get(0).getSHA256Fingerprint().equals(leafReport.getSHA256Fingerprint())) {
                chainIsOrdered = false;
            } else {
                chainIsOrdered = checkCertifiteChainIsOrdered(certificateReportList);
            }
            //Try to build a chain
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
                    //Could not find issuer for certificate - check if its in the trust store
                    if (TrustAnchorManager.getInstance().isTrustAnchor(tempCertificate.getX509Certificate().getIssuerX500Principal())) {
                        //Certificate is issued by trust anchor
                        LOGGER.debug("Could find issuer");
                        chainIsComplete = true;
                        org.bouncycastle.asn1.x509.Certificate trustAnchorCertificate = TrustAnchorManager.getInstance().getTrustAnchorCertificate(tempCertificate.getX509Certificate().getIssuerX500Principal());
                        if (trustAnchorCertificate != null) {
                            CertificateReport trustAnchorReport = CertificateReportGenerator.generateReport(trustAnchorCertificate);
                            orderedCertificateChain.add(trustAnchorReport);
                            trustAnchorReport.setTrustAnchor(true);
                            trustAnchor = trustAnchorReport;
                        }
                    } else {
                        LOGGER.debug("Could not find issuer");
                        chainIsComplete = false;
                    }
                    break;
                }
            }
        } else {
            chainIsOrdered = true; //there is no leaf certificate - so i guess this is ordered?
            containsValidLeaf = false;
        }
        containsNotYetValid = false;
        containsExpired = false;
        containsWeakSignedNonTruststoresCertificates = false;
        for (CertificateReport report : certificateReportList) {
            if (report.getValidFrom().after(new Date())) {
                containsNotYetValid = true;
            }
            if (report.getValidTo().before(new Date())) {
                containsExpired = true;
            }
            if (Objects.equals(report.isTrustAnchor(), Boolean.FALSE) && Objects.equals(report.getSelfSigned(), Boolean.FALSE) && report.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.MD5 || report.getSignatureAndHashAlgorithm().getHashAlgorithm() == HashAlgorithm.SHA1) {
                containsWeakSignedNonTruststoresCertificates = true;
            }
        }
        for (CertificateReport report : certificateReportList) {
            if (Objects.equals(report.isTrustAnchor(), Boolean.FALSE) && Objects.equals(report.getSelfSigned(), Boolean.TRUE) && Objects.equals(report.getLeafCertificate(), Boolean.TRUE)) {
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
        if (Objects.equals(containsMultipleLeafs, Boolean.TRUE)) {
            certificateIssues.add(CertificateIssue.MULTIPLE_LEAFS);
        }
        if (Objects.equals(containsWeakSignedNonTruststoresCertificates, Boolean.TRUE)) {
            certificateIssues.add(CertificateIssue.WEAK_SIGNATURE_OR_HASH_ALGORITHM);
        }
        if (Objects.equals(chainIsComplete, Boolean.TRUE) && Objects.equals(containsValidLeaf, Boolean.TRUE) && Objects.equals(containsExpired, Boolean.FALSE) && Objects.equals(containsNotYetValid, Boolean.FALSE)) {
            CertPathValidationResult certPathValidationResult = evaluateGeneralTrust(orderedCertificateChain);
            generallyTrusted = certPathValidationResult.isValid();
            if (!generallyTrusted) {
                CertPathValidationException[] causes = certPathValidationResult.getCauses();
                if (causes != null) {
                    for (CertPathValidationException exception : causes) {
                        exception.printStackTrace();
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

    public Boolean getContainsWeakSignedNonTruststoresCertificates() {
        return containsWeakSignedNonTruststoresCertificates;
    }

    public void setContainsWeakSignedNonTruststoresCertificates(Boolean containsWeakSignedNonTruststoresCertificates) {
        this.containsWeakSignedNonTruststoresCertificates = containsWeakSignedNonTruststoresCertificates;
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

    public Boolean getContainsMultipleLeafs() {
        return containsMultipleLeafs;
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

    public final boolean checkCertifiteChainIsOrdered(List<CertificateReport> reports) {
        if (reports.isEmpty()) {
            return true; //i guess ^^
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

    public final boolean isCertificateSuiteableForHost(X509Certificate cert, String host) {
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
            return null;//Emtpy chains & only root ca's are considered not generally trusted i guess
        }
        X509CertificateHolder[] certPath = new X509CertificateHolder[orderedCertificateChain.size()];
        for (int i = 0; i < orderedCertificateChain.size(); i++) {
            certPath[i] = orderedCertificateChain.get(i).getCertificateHolder();
        }
        CertPath path = new CertPath(certPath);
        X509ContentVerifierProviderBuilder verifier = new JcaX509ContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
        CertPathValidationResult result = path.validate(new CertPathValidation[]{new ParentCertIssuedValidation(verifier), new BasicConstraintsValidation(), new KeyUsageValidation()});

        return result;
    }
}
