/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.trust;

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

    /** Default constructor for deserialization. */
    @SuppressWarnings("unused")
    private TrustPlatform() {
        blockedCertificateEntries = null;
        certificateEntries = null;
        lastUpdate = null;
        platform = null;
        url = null;
        version = null;
    }

    /**
     * Constructs a new TrustPlatform with the specified parameters.
     *
     * @param platform the name of the trust platform
     * @param version the version of the trust platform
     * @param url the URL where the trust store was fetched from
     * @param lastUpdate the date when the trust store was last updated
     * @param certificateEntries the list of trusted certificate entries
     * @param blockedCertificateEntries the list of blocked certificate entries
     */
    public TrustPlatform(
            String platform,
            String version,
            String url,
            Date lastUpdate,
            List<CertificateEntry> certificateEntries,
            List<CertificateEntry> blockedCertificateEntries) {
        this.platform = platform;
        this.version = version;
        this.url = url;
        this.lastUpdate = lastUpdate;
        this.certificateEntries = certificateEntries;
        this.blockedCertificateEntries = blockedCertificateEntries;
    }

    /**
     * Returns the name of the trust platform.
     *
     * @return the platform name
     */
    public String getPlatform() {
        return platform;
    }

    /**
     * Returns the version of the trust platform.
     *
     * @return the platform version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Returns the URL where the trust store was fetched from.
     *
     * @return the trust store URL
     */
    public String getUrl() {
        return url;
    }

    /**
     * Returns the date when the trust store was last updated.
     *
     * @return the last update date
     */
    public Date getLastUpdate() {
        return lastUpdate;
    }

    /**
     * Returns the list of trusted certificate entries.
     *
     * @return the list of trusted certificates
     */
    public List<CertificateEntry> getCertificateEntries() {
        return certificateEntries;
    }

    /**
     * Returns the list of blocked certificate entries.
     *
     * @return the list of blocked certificates
     */
    public List<CertificateEntry> getBlockedCertificateEntries() {
        return blockedCertificateEntries;
    }

    /**
     * Checks if a certificate with the given subject name is in the trusted certificate list.
     *
     * @param subject the subject name to check
     * @return true if the certificate is trusted, false otherwise
     */
    public boolean isTrusted(String subject) {
        for (CertificateEntry entry : certificateEntries) {
            if (entry.getSubjectName().equals(subject)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a certificate with the given subject name is in the blocked certificate list.
     *
     * @param subject the subject name to check
     * @return true if the certificate is blacklisted, false otherwise
     */
    public boolean isBlacklisted(String subject) {
        for (CertificateEntry entry : blockedCertificateEntries) {
            if (entry.getSubjectName().equals(subject)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the trust anchor as a CertificateEntry for the Subject.If the subject is not trusted
     * or not found null is returned
     *
     * @param subject The subject to search for
     * @return The relevant CertificateEntry or null if not found
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
     * Returns the blocked certificate as a CertificateEntry for the Subject. If the subject is not
     * blacklisted or not found null is returned
     *
     * @param subject The subject to search for
     * @return The relevant CertificateEntry or null if not found
     */
    public CertificateEntry getBlacklistedCertificateEntry(String subject) {
        for (CertificateEntry entry : blockedCertificateEntries) {
            if (entry.getSubjectName().equals(subject)) {
                return entry;
            }
        }
        return null;
    }
}
