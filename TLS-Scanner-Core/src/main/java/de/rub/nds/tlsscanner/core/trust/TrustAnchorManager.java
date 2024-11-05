/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.trust;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;
import javax.security.auth.x500.X500Principal;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;

public class TrustAnchorManager {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<TrustPlatform> trustPlatformList;

    private HashMap<String, CertificateEntry> trustAnchors;

    private HashMap<String, CertificateEntry> customTrustAnchors;

    private static TrustAnchorManager INSTANCE = null;

    private Set<TrustAnchor> trustAnchorSet;

    private Set<X509Certificate> asn1CaCertificateSet;

    public static synchronized TrustAnchorManager getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new TrustAnchorManager();
        }
        return INSTANCE;
    }

    private TrustAnchorManager() {
        trustPlatformList = new LinkedList<>();
        try {
            trustPlatformList.add(readPlatform("google_aosp.yaml"));
            trustPlatformList.add(readPlatform("microsoft_windows.yaml"));
            trustPlatformList.add(readPlatform("mozilla_nss.yaml"));
            trustPlatformList.add(readPlatform("openjdk.yaml"));
            trustPlatformList.add(readPlatform("oracle_java.yaml"));
            trustPlatformList.add(readPlatform("apple.yaml"));

            trustAnchors = new HashMap<>();
            customTrustAnchors = new HashMap<>();
            for (TrustPlatform platform : trustPlatformList) {
                for (CertificateEntry entry : platform.getCertificateEntries()) {
                    if (!trustAnchors.containsKey(entry.getFingerprint())) {
                        trustAnchors.put(entry.getFingerprint(), entry);
                    }
                }
                for (CertificateEntry entry : platform.getBlockedCertificateEntries()) {
                    if (!trustAnchors.containsKey(entry.getFingerprint())) {
                        trustAnchors.put(entry.getFingerprint(), entry);
                    }
                }
            }

            this.trustAnchorSet = getFullTrustAnchorSet();
            this.asn1CaCertificateSet = getFullCaCertificateSet();

        } catch (IOException | IllegalArgumentException ex) {
            trustAnchorSet = null;
            trustAnchors = null;
            trustPlatformList = null;
            asn1CaCertificateSet = null;
            LOGGER.error(
                    "Could not load TrustAnchors. This means that you are running TLS-Scanner without its submodules. "
                            + "If you want to evaluate if certificates are trusted by browsers you need to initialize submodules."
                            + "You can do this by running the following command:'git submodule update --init --recursive'");
            LOGGER.debug(ex);
        }
    }

    public boolean isInitialized() {
        return trustAnchorSet != null && trustPlatformList != null && trustAnchors != null;
    }

    private TrustPlatform readPlatform(String name) throws IOException {
        InputStream resourceAsStream =
                TrustAnchorManager.class.getClassLoader().getResourceAsStream("trust/" + name);
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        TrustPlatform loadedPlatform = mapper.readValue(resourceAsStream, TrustPlatform.class);
        return loadedPlatform;
    }

    public List<TrustPlatform> getTrustPlatformList() {
        return trustPlatformList;
    }

    public boolean isTrustAnchor(CertificateReport report) {
        if (trustAnchors.containsKey(report.getIssuer())) {
            LOGGER.debug("Found a trustAnchor for Issuer report");
            CertificateEntry entry = trustAnchors.get(report.getIssuer());
            if (entry.getFingerprint().equals(report.getSHA256Fingerprint())) {
                return true;
            } else {
                LOGGER.warn("TrustAnchor hash does not match stored fingerprint");
                return false;
            }
        } else {
            return false;
        }
    }

    public boolean isTrustAnchor(X500Principal principal) {
        for (TrustAnchor anchor : trustAnchorSet) {
            if (anchor.getTrustedCert().getSubjectX500Principal().equals(principal)) {
                return true;
            }
        }
        return false;
    }

    private Set<TrustAnchor> getFullTrustAnchorSet() {
        Set<TrustAnchor> trustedAnchors = new HashSet<>();
        try {
            int i = 0;
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            for (CertificateEntry entry : trustAnchors.values()) {
                InputStream resourceAsStream =
                        TrustAnchorManager.class
                                .getClassLoader()
                                .getResourceAsStream("trust/" + entry.getFingerprint() + ".pem");
                try {
                    X509Certificate ca =
                            (X509Certificate)
                                    CertificateFactory.getInstance("X.509")
                                            .generateCertificate(
                                                    new BufferedInputStream(resourceAsStream));
                    keyStore.setCertificateEntry("" + i, ca);

                } catch (CertificateException ex) {
                    LOGGER.error(
                            "Could not load Certificate:"
                                    + entry.getSubjectName()
                                    + "/"
                                    + entry.getFingerprint(),
                            ex);
                }
                i++;
            }
            PKIXParameters params = new PKIXParameters(keyStore);
            /* Converts the immutable trustAnchorSet (read only) to a set with write access */
            trustedAnchors.addAll(params.getTrustAnchors());
            return trustedAnchors;

        } catch (IOException
                | NoSuchAlgorithmException
                | CertificateException
                | KeyStoreException
                | InvalidAlgorithmParameterException ex) {
            LOGGER.error("Could not build TrustAnchorSet", ex);
        }
        return new HashSet<>();
    }

    public Set<TrustAnchor> getTrustAnchorSet() {
        return trustAnchorSet;
    }

    public X509Certificate getTrustAnchorX509Certificate(X500Principal principal) {
        for (TrustAnchor anchor : trustAnchorSet) {
            if (anchor.getTrustedCert().getSubjectX500Principal().equals(principal)) {
                return anchor.getTrustedCert();
            }
        }
        return null;
    }

    public X509Certificate getTrustAnchorCertificate(X500Principal principal) {
        for (X509Certificate cert : asn1CaCertificateSet) {
            if (principal.equals(cert.getSubjectX500Principal())) {
                return cert;
            }
        }
        return null;
    }

    private Set<X509Certificate> getFullCaCertificateSet() {
        Set<X509Certificate> certificateSet = new HashSet<>();
        for (CertificateEntry entry : trustAnchors.values()) {
            InputStream resourceAsStream =
                    TrustAnchorManager.class
                            .getClassLoader()
                            .getResourceAsStream("trust/" + entry.getFingerprint() + ".pem");
            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                X509Certificate cert =
                        (X509Certificate) certFactory.generateCertificate(resourceAsStream);
                certificateSet.add(cert);
            } catch (CertificateException ex) {
                LOGGER.error(
                        "Could not load Certificate:"
                                + entry.getSubjectName()
                                + "/"
                                + entry.getFingerprint(),
                        ex);
            }
        }
        return certificateSet;
    }

    private List<X509Certificate> getCustomCA(List<String> customCAPaths) {
        List<X509Certificate> certX509List = new ArrayList<>();
        for (String filepath : customCAPaths) {
            try (InputStream inStream = new FileInputStream(filepath)) {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) certFactory.generateCertificate(inStream);
                certX509List.add(cert);
            } catch (CertificateException | IOException ex) {
                LOGGER.error("Couldn't load the CA: " + filepath, ex);
            }
        }
        return certX509List;
    }

    public void addCustomCA(List<String> customCAPaths) {
        List<X509Certificate> customCAList = getCustomCA(customCAPaths);
        KeyStore keyStore = null;

        // Initializes the keyStore
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
        } catch (KeyStoreException
                | CertificateException
                | NoSuchAlgorithmException
                | IOException ex) {
            throw new RuntimeException("Couldn't initialize keyStore,", ex);
        }

        for (int i = 0; i < customCAList.size(); i++) {
            X509Certificate cert = customCAList.get(i);
            try {
                keyStore.setCertificateEntry("custom_" + i, cert);
            } catch (KeyStoreException ex) {
                throw new RuntimeException(
                        "Couldn't add the certificate:" + customCAPaths.get(i) + " to the keyStore",
                        ex);
            }

            /*
             * Creates a SHA256 fingerprint for each CA in customCAList. For each CA in customCAList the subject and
             * fingerprint of each CA is stored in a certEntry. Each certEntry is then added to the trustAnchors and
             * each CA is added to the asn1CaCertificateSet.
             */
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] sha256Fingerprint = digest.digest(cert.getEncoded());
                String fingerprintHex = Hex.toHexString(sha256Fingerprint);
                CertificateEntry certEntry =
                        new CertificateEntry(
                                cert.getSubjectX500Principal().getName(), fingerprintHex);
                this.trustAnchors.put(fingerprintHex, certEntry);
                this.customTrustAnchors.put(fingerprintHex, certEntry);
                this.asn1CaCertificateSet.add(cert);
            } catch (NoSuchAlgorithmException | CertificateEncodingException ex) {
                LOGGER.error(
                        "Couldn't add CA "
                                + customCAList.get(i)
                                + " to either trustAnchor or asn1CaCertificateSet.",
                        ex);
            }
        }

        /*
         * Adds all trusted CA's from the keyStore to the trustAnchorSet in a way that the resulting trustAnchorSet is
         * mutable. Otherwise, the trustAnchorSet would be immutable so that adding further certificates to the
         * trustAnchorSet would be impossible.
         */
        try {
            PKIXParameters params = new PKIXParameters(keyStore);
            for (TrustAnchor entry : params.getTrustAnchors()) {
                this.trustAnchorSet.add(entry);
            }
        } catch (InvalidAlgorithmParameterException | KeyStoreException ex) {
            LOGGER.error("The keyStore doesn't contain at least one trusted CA", ex);
        }
    }

    public boolean hasCustomTrustAnchros() {
        return customTrustAnchors != null && !customTrustAnchors.isEmpty();
    }

    public boolean isCustomTrustAnchor(CertificateReport report) {
        if (customTrustAnchors.containsKey(report.getIssuer())) {
            LOGGER.debug("Found a customTrustAnchor for Issuer report");
            CertificateEntry entry = customTrustAnchors.get(report.getIssuer());
            if (entry.getFingerprint().equals(report.getSHA256Fingerprint())) {
                return true;
            } else {
                LOGGER.warn("CustomTrustAnchor hash does not match stored fingerprint");
                return false;
            }
        } else {
            return false;
        }
    }
}
