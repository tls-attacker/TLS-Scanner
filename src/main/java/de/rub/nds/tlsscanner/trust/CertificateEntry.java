/*
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.trust;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *
 * @author ic0ns
 */
public class CertificateEntry {

    @JsonProperty("subject_name")
    private final String subjectName;

    @JsonProperty("fingerprint")
    private final String fingerprint;

    public CertificateEntry(String subjectName, String fingerprint) {
        this.subjectName = subjectName;
        this.fingerprint = fingerprint;
    }

    public CertificateEntry() {
        subjectName = null;
        fingerprint = null;
    }

    public String getSubjectName() {
        return subjectName;
    }

    public String getFingerprint() {
        return fingerprint;
    }

}
