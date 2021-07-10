/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
