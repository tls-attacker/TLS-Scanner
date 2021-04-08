/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.trust;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Date;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class TrustPlatform {

    @JsonProperty("platform")
    private final String platform;
    @JsonProperty("version")
    private final String version;
    @JsonProperty("url")
    private final String url;
    @JsonProperty("date_fetched")
    private final Date lastUpdate;
    @JsonProperty("trusted_certificates")
    private final List<CertificateEntry> certificateEntries;
    @JsonProperty("blocked_certificates")
    private final List<CertificateEntry> blockedCertificateEntries;

    public TrustPlatform() {
        blockedCertificateEntries = null;
        certificateEntries = null;
        lastUpdate = null;
        platform = null;
        url = null;
        version = null;
    }

    public TrustPlatform(String platform, String version, String url, Date lastUpdate,
        List<CertificateEntry> certificateEntries, List<CertificateEntry> blockedCertificateEntries) {
        this.platform = platform;
        this.version = version;
        this.url = url;
        this.lastUpdate = lastUpdate;
        this.certificateEntries = certificateEntries;
        this.blockedCertificateEntries = blockedCertificateEntries;
    }

    public String getPlatform() {
        return platform;
    }

    public String getVersion() {
        return version;
    }

    public String getUrl() {
        return url;
    }

    public Date getLastUpdate() {
        return lastUpdate;
    }

    public List<CertificateEntry> getCertificateEntries() {
        return certificateEntries;
    }

    public List<CertificateEntry> getBlockedCertificateEntries() {
        return blockedCertificateEntries;
    }

    public boolean isTrusted(String subject) {
        for (CertificateEntry entry : certificateEntries) {
            if (entry.getSubjectName().equals(subject)) {
                return true;
            }
        }
        return false;
    }

    public boolean isBlacklisted(String subject) {
        for (CertificateEntry entry : blockedCertificateEntries) {
            if (entry.getSubjectName().equals(subject)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the trust anchor as a CertificateEntry for the Subject.If the subject is not trusted or not found null is
     * returned
     *
     * @param  subject
     *                 The subject to search for
     * @return         The relevant CertificateEntry or null if not found
     */
    public CertificateEntry getTrustedCertificateEntry(String subject) {
        for (CertificateEntry entry : certificateEntries) {
            if (entry.getSubjectName().equals(subject)) {
                return entry;
            }
        }
        return null;
    }

    /**
     * Returns the trust anchor as a CertificateEntry for the Subject.If the subject is not trusted or not found null is
     * returned
     *
     * @param  subject
     *                 The subject to search for
     * @return         The relevant CertificateEntry or null if not found
     */
    public CertificateEntry getBlacklistedCertificateEntry(String subject) {
        for (CertificateEntry entry : certificateEntries) {
            if (entry.getSubjectName().equals(subject)) {
                return entry;
            }
        }
        return null;
    }
}
