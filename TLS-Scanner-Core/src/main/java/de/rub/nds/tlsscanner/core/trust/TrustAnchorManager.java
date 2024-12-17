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
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateReport;
import de.rub.nds.x509attacker.filesystem.CertificateIo;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class TrustAnchorManager {

    private static final String TRUST_RESOURCE_PATH = "trust/";

    private static final Logger LOGGER = LogManager.getLogger();

    private List<TrustPlatform> trustPlatformList;
    private HashMap<String, CertificateEntry> trustAnchors;
    private HashMap<String, CertificateEntry> customTrustAnchors;

    private static final TrustAnchorManager INSTANCE = new TrustAnchorManager();

    public static synchronized TrustAnchorManager getInstance() {
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
        } catch (IOException | IllegalArgumentException ex) {
            trustAnchors = null;
            trustPlatformList = null;
            LOGGER.error(
                    "Could not load TrustAnchors. This means that you are running TLS-Scanner without its submodules. "
                            + "If you want to evaluate if certificates are trusted by browsers you need to initialize submodules."
                            + "You can do this by running the following command:'git submodule update --init --recursive'");
            LOGGER.debug(ex);
        }
    }

    public boolean isInitialized() {
        return trustPlatformList != null && trustAnchors != null;
    }

    private TrustPlatform readPlatform(String name) throws IOException {
        InputStream resourceAsStream =
                TrustAnchorManager.class
                        .getClassLoader()
                        .getResourceAsStream(TRUST_RESOURCE_PATH + name);
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        return mapper.readValue(resourceAsStream, TrustPlatform.class);
    }

    public List<TrustPlatform> getTrustPlatformList() {
        return trustPlatformList;
    }

    public boolean isTrustAnchor(byte[] fingerprint) {
        return trustAnchors.containsKey(
                ArrayConverter.bytesToHexString(fingerprint, false, false).replace(" ", ""));
    }

    public void loadTrustAnchorsFromFiles(List<String> customCAPaths) {
        for (String filepath : customCAPaths) {
            try {
                X509Certificate x509Certificate =
                        CertificateIo.readPemChain(new File(filepath)).getCertificate(0);
                customTrustAnchors.put(
                        ArrayConverter.bytesToHexString(
                                        x509Certificate.getSha256Fingerprint(), false, false)
                                .replace(" ", ""),
                        new CertificateEntry(
                                x509Certificate.getSubjectString(),
                                ArrayConverter.bytesToHexString(
                                                x509Certificate.getSha256Fingerprint(),
                                                false,
                                                false)
                                        .replace(" ", "")));
            } catch (IOException e) {
                LOGGER.warn("Could not read custom CA from file: {}", filepath);
            }
        }
    }

    public boolean hasCustomTrustAnchros() {
        return customTrustAnchors != null && !customTrustAnchors.isEmpty();
    }

    public boolean isCustomTrustAnchor(CertificateReport report) {
        if (customTrustAnchors.containsKey(report.getIssuer())) {
            LOGGER.debug("Found a customTrustAnchor for Issuer report");
            CertificateEntry entry = customTrustAnchors.get(report.getIssuer());
            if (Arrays.equals(
                    ArrayConverter.hexStringToByteArray(entry.getFingerprint()),
                    report.getSHA256Fingerprint())) {
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
