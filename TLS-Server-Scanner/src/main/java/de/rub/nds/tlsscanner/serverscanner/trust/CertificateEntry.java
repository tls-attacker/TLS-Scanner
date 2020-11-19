/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.trust;

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
