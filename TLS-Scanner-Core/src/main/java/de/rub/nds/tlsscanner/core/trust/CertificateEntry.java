/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.trust;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CertificateEntry {

    @JsonProperty("subject_name")
    private final String subjectName;

    @JsonProperty("fingerprint")
    private final String fingerprint;

    /**
     * Constructs a new CertificateEntry with the specified subject name and fingerprint.
     *
     * @param subjectName the subject name of the certificate
     * @param fingerprint the SHA-256 fingerprint of the certificate
     */
    public CertificateEntry(String subjectName, String fingerprint) {
        this.subjectName = subjectName;
        this.fingerprint = fingerprint;
    }

    /** Default constructor for CertificateEntry. Initializes all fields to null. */
    public CertificateEntry() {
        subjectName = null;
        fingerprint = null;
    }

    /**
     * Returns the subject name of the certificate.
     *
     * @return the subject name
     */
    public String getSubjectName() {
        return subjectName;
    }

    /**
     * Returns the SHA-256 fingerprint of the certificate.
     *
     * @return the certificate fingerprint
     */
    public String getFingerprint() {
        return fingerprint;
    }
}
