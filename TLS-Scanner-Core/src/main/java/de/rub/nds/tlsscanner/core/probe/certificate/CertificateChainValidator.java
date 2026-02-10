/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.certificate;

import de.rub.nds.tlsscanner.core.trust.TrustAnchorManager;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CertificateChainValidator {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Validates a certificate chain against the trust anchors by checking if any certificate in the
     * chain is a trust anchor or if the chain terminates at a trust anchor.
     *
     * @param certificateChain The certificate chain to validate (leaf first)
     * @return true if the chain validates to a trusted root, false otherwise
     */
    public static boolean validateCertificateChain(List<X509Certificate> certificateChain) {
        if (certificateChain == null || certificateChain.isEmpty()) {
            LOGGER.debug("Certificate chain is null or empty");
            return false;
        }

        TrustAnchorManager trustManager = TrustAnchorManager.getInstance();
        if (!trustManager.isInitialized()) {
            LOGGER.debug("TrustAnchorManager is not initialized");
            return false;
        }

        // Check if any certificate in the chain is a trust anchor
        for (X509Certificate cert : certificateChain) {
            // Create a temporary CertificateReport to check trust anchor status
            CertificateReport tempReport = new CertificateReport();
            tempReport.setIssuer(cert.getIssuerString());
            tempReport.setSha256Fingerprint(cert.getSha256Fingerprint());

            if (trustManager.isTrustAnchor(tempReport)) {
                LOGGER.debug("Found trust anchor in certificate chain");
                return true;
            }
        }

        // Check if the last certificate (root) has an issuer that is a trust anchor
        if (!certificateChain.isEmpty()) {
            X509Certificate lastCert = certificateChain.get(certificateChain.size() - 1);
            // If the last certificate is self-signed, we already checked it above
            if (!lastCert.getIssuerString().equals(lastCert.getSubjectString())) {
                // Check if the issuer is a trust anchor
                javax.security.auth.x500.X500Principal issuerPrincipal =
                        new javax.security.auth.x500.X500Principal(lastCert.getIssuerString());
                if (trustManager.isTrustAnchor(issuerPrincipal)) {
                    LOGGER.debug("Certificate chain terminates at a trust anchor");
                    return true;
                }
            }
        }

        LOGGER.debug("Certificate chain does not validate to a trust anchor");
        return false;
    }

    /**
     * Validates if a single certificate in a chain is trusted. This is done by checking if the
     * certificate chain containing this certificate validates to a trusted root.
     *
     * @param certificate The certificate to check
     * @param fullChain The full certificate chain containing the certificate
     * @return true if the certificate is part of a valid chain, false otherwise
     */
    public static boolean isCertificateTrusted(
            X509Certificate certificate, List<X509Certificate> fullChain) {
        if (certificate == null || fullChain == null || fullChain.isEmpty()) {
            return false;
        }

        // Find the position of the certificate in the chain
        int certIndex = -1;
        for (int i = 0; i < fullChain.size(); i++) {
            X509Certificate cert = fullChain.get(i);
            if (cert.getSha256Fingerprint().equals(certificate.getSha256Fingerprint())) {
                certIndex = i;
                break;
            }
        }

        if (certIndex == -1) {
            LOGGER.debug("Certificate not found in the provided chain");
            return false;
        }

        // Create a subchain from the certificate to the end of the chain
        List<X509Certificate> subChain = fullChain.subList(certIndex, fullChain.size());

        // Validate the subchain
        return validateCertificateChain(subChain);
    }
}
