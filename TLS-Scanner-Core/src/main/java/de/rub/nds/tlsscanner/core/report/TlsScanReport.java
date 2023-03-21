/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.report;

import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.leak.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.core.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public abstract class TlsScanReport extends ScanReport {

    private ProtocolType protocolType = null;

    // Version
    private List<ProtocolVersion> versions = null;

    // Ciphers
    private List<VersionSuiteListPair> versionSuitePairs = null;
    private Set<CipherSuite> cipherSuites = null;

    // Compression
    private List<CompressionMethod> supportedCompressionMethods = null;

    // Attacks
    private List<InformationLeakTest<PaddingOracleTestInfo>> paddingOracleTestResultList;
    private KnownPaddingOracleVulnerability knownPaddingOracleVulnerability = null;

    // Extensions
    private List<String> supportedAlpns = null;

    // Certificate
    private List<CertificateChain> certificateChainList;

    // DTLS
    private Integer totalReceivedRetransmissions = 0;
    private Map<HandshakeMessageType, Integer> retransmissionCounters;

    // Entropy
    private List<EntropyReport> entropyReportList;

    // Scan Timestamps
    private long scanStartTime;
    private long scanEndTime;

    public TlsScanReport() {
        super();
    }

    public synchronized ProtocolType getProtocolType() {
        return protocolType;
    }

    public synchronized void setProtocolType(ProtocolType protocolType) {
        this.protocolType = protocolType;
    }

    public synchronized List<ProtocolVersion> getVersions() {
        return versions;
    }

    public synchronized void setVersions(List<ProtocolVersion> supportedVersions) {
        this.versions = supportedVersions;
    }

    public synchronized List<VersionSuiteListPair> getVersionSuitePairs() {
        return versionSuitePairs;
    }

    public synchronized void setVersionSuitePairs(List<VersionSuiteListPair> versionSuitePairs) {
        this.versionSuitePairs = versionSuitePairs;
    }

    public synchronized Set<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public synchronized void setCipherSuites(Set<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public synchronized void addCipherSuites(Set<CipherSuite> cipherSuites) {
        if (this.cipherSuites == null) {
            this.cipherSuites = new HashSet<>();
        }
        this.cipherSuites.addAll(cipherSuites);
    }

    public synchronized List<CompressionMethod> getSupportedCompressionMethods() {
        return supportedCompressionMethods;
    }

    public synchronized void setSupportedCompressionMethods(
            List<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public synchronized List<InformationLeakTest<PaddingOracleTestInfo>>
            getPaddingOracleTestResultList() {
        return paddingOracleTestResultList;
    }

    public synchronized void setPaddingOracleTestResultList(
            List<InformationLeakTest<PaddingOracleTestInfo>> paddingOracleTestResultList) {
        this.paddingOracleTestResultList = paddingOracleTestResultList;
    }

    public synchronized KnownPaddingOracleVulnerability getKnownPaddingOracleVulnerability() {
        return knownPaddingOracleVulnerability;
    }

    public synchronized void setKnownPaddingOracleVulnerability(
            KnownPaddingOracleVulnerability knownPaddingOracleVulnerability) {
        this.knownPaddingOracleVulnerability = knownPaddingOracleVulnerability;
    }

    public synchronized List<String> getSupportedAlpns() {
        return supportedAlpns;
    }

    public synchronized void setSupportedAlpns(List<String> supportedAlpns) {
        this.supportedAlpns = supportedAlpns;
    }

    public synchronized List<CertificateChain> getCertificateChainList() {
        return certificateChainList;
    }

    public synchronized void setCertificateChainList(List<CertificateChain> certificateChainList) {
        this.certificateChainList = certificateChainList;
    }

    public synchronized Integer getTotalReceivedRetransmissions() {
        return totalReceivedRetransmissions;
    }

    public synchronized void setTotalReceivedRetransmissions(Integer totalReceivedRetransmissions) {
        this.totalReceivedRetransmissions = totalReceivedRetransmissions;
    }

    public synchronized Map<HandshakeMessageType, Integer> getRetransmissionCounters() {
        return retransmissionCounters;
    }

    public synchronized void setRetransmissionCounters(
            Map<HandshakeMessageType, Integer> retransmissionCounters) {
        this.retransmissionCounters = retransmissionCounters;
    }

    public synchronized List<EntropyReport> getEntropyReportList() {
        return entropyReportList;
    }

    public synchronized void setEntropyReportList(List<EntropyReport> entropyReportList) {
        this.entropyReportList = entropyReportList;
    }

    public synchronized long getScanStartTime() {
        return scanStartTime;
    }

    public synchronized void setScanStartTime(long scanStartTime) {
        this.scanStartTime = scanStartTime;
    }

    public synchronized long getScanEndTime() {
        return scanEndTime;
    }

    public synchronized void setScanEndTime(long scanEndTime) {
        this.scanEndTime = scanEndTime;
    }
}
