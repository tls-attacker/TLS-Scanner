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
import de.rub.nds.x509attacker.signatureengine.keyparsers.PemUtil;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

public class TrustAnchorManager {

    private static final Logger LOGGER = LogManager.getLogger();

    private List<TrustPlatform> trustPlatformList;

    private HashMap<String, CertificateEntry> trustAnchors;

    private HashMap<String, CertificateEntry> customTrustAnchors;

    private static TrustAnchorManager INSTANCE = null;

    private Set<TrustAnchor> trustAnchorSet;
    private Set<Certificate> asn1CaCertificateSet;

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

    public Certificate getTrustAnchorCertificate(X500Principal principal) {
        for (Certificate cert : asn1CaCertificateSet) {
            try {
                X509Certificate x509Cert = new X509CertificateObject(cert);
                if (principal.equals(x509Cert.getSubjectX500Principal())) {
                    return cert;
                }
            } catch (CertificateParsingException ex) {
                LOGGER.error("Could not parse Certificate", ex);
            }
        }
        return null;
    }

    private Set<Certificate> getFullCaCertificateSet() {
        Set<Certificate> certificateSet = new HashSet<>();
        for (CertificateEntry entry : trustAnchors.values()) {
            InputStream resourceAsStream =
                    TrustAnchorManager.class
                            .getClassLoader()
                            .getResourceAsStream("trust/" + entry.getFingerprint() + ".pem");
            try {
                org.bouncycastle.crypto.tls.Certificate cert =
                        PemUtil.readCertificate(resourceAsStream);
                certificateSet.add(cert.getCertificateAt(0));
            } catch (IOException | CertificateException ex) {
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

    private List<org.bouncycastle.crypto.tls.Certificate> getCustomCA(List<String> customCAPaths) {
        List<org.bouncycastle.crypto.tls.Certificate> certX509List = new ArrayList<>();
        for (String filepath : customCAPaths) {
            try {
                certX509List.add(PemUtil.readCertificate(new File(filepath)));
            } catch (CertificateException | IOException ex) {
                LOGGER.error("Could't load the CA: " + filepath, ex);
            }
        }
        return certX509List;
    }

    public void addCustomCA(List<String> customCAPaths) {
        List<org.bouncycastle.crypto.tls.Certificate> customCAList = getCustomCA(customCAPaths);
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
            org.bouncycastle.crypto.tls.Certificate cert = customCAList.get(i);
            // Converts each certificate in customCAList to a x.509 formatted certificate and adds
            // it to the keystore.
            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X509");
                keyStore.setCertificateEntry(
                        "custom_" + i,
                        certFactory.generateCertificate(
                                new ByteArrayInputStream(cert.getCertificateAt(0).getEncoded())));
            } catch (CertificateException | IOException | KeyStoreException ex) {
                throw new RuntimeException(
                        "Couldn't add the certificate:" + customCAPaths.get(i) + "to the keyStore",
                        ex);
            }

            /*
             * Creates a SHA256 fingerprint for each CA in customCAList. For each CA in customCAList the subject and
             * fingerprint of each CA is stored in a certEntry. Each certEntry is then added to the trustAnchors and
             * each CA is added to the asn1CaCertificateSet.
             */
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] sha256Fingerprint = digest.digest(cert.getCertificateAt(0).getEncoded());
                CertificateEntry certEntry =
                        new CertificateEntry(
                                cert.getCertificateAt(0).getSubject().toString(),
                                sha256Fingerprint.toString());
                this.trustAnchors.put(sha256Fingerprint.toString(), certEntry);
                this.customTrustAnchors.put(sha256Fingerprint.toString(), certEntry);
                this.asn1CaCertificateSet.add(cert.getCertificateAt(0));
            } catch (NoSuchAlgorithmException | IOException ex) {
                LOGGER.error(
                        "Couldn't add CA "
                                + customCAList.get(i)
                                + "to either trustAnchor or asn1CaCertificateSet.",
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
