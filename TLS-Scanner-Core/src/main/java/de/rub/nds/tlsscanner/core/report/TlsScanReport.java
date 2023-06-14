/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.report;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.MapResult;
import de.rub.nds.scanner.core.constants.SetResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.leak.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.core.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public abstract class TlsScanReport extends ScanReport {

    private ProtocolType protocolType = null;

    private KnownPaddingOracleVulnerability knownPaddingOracleVulnerability = null;

    // Extensions
    private List<String> supportedAlpns = null;

    // DTLS
    private Integer totalReceivedRetransmissions = 0;

    // Scan Timestamps
    private long scanStartTime;
    private long scanEndTime;

    // If the peer closes the connection by itself if nothing gets sent
    private Long closedAfterFinishedDelta;
    private Long closedAfterAppDataDelta;

    public TlsScanReport() {
        super();
    }

    public synchronized ProtocolType getProtocolType() {
        return protocolType;
    }

    public synchronized void setProtocolType(ProtocolType protocolType) {
        this.protocolType = protocolType;
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

    public synchronized Integer getTotalReceivedRetransmissions() {
        return totalReceivedRetransmissions;
    }

    public synchronized void setTotalReceivedRetransmissions(Integer totalReceivedRetransmissions) {
        this.totalReceivedRetransmissions = totalReceivedRetransmissions;
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

    public synchronized Boolean getCcaSupported() {
        return this.getResult(TlsAnalyzedProperty.SUPPORTS_CCA) == TestResults.TRUE;
    }

    public synchronized Boolean getCcaRequired() {
        return this.getResult(TlsAnalyzedProperty.REQUIRES_CCA) == TestResults.TRUE;
    }

    public synchronized Map<HandshakeMessageType, Integer> getRetransmissionCounters() {
        @SuppressWarnings("unchecked")
        MapResult<HandshakeMessageType, Integer> mapResult =
                (MapResult<HandshakeMessageType, Integer>)
                        getMapResult(TlsAnalyzedProperty.MAP_RETRANSMISSION_COUNTERS);
        return mapResult == null ? null : mapResult.getMap();
    }

    public synchronized Set<CipherSuite> getSupportedCipherSuites() {
        @SuppressWarnings("unchecked")
        SetResult<CipherSuite> setResult =
                (SetResult<CipherSuite>) getSetResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES);
        return setResult == null ? null : setResult.getSet();
    }

    public synchronized List<EntropyReport> getEntropyReports() {
        @SuppressWarnings("unchecked")
        ListResult<EntropyReport> listResult =
                (ListResult<EntropyReport>) getListResult(TlsAnalyzedProperty.ENTROPY_REPORTS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<InformationLeakTest<PaddingOracleTestInfo>>
            getPaddingOracleTestResultList() {
        @SuppressWarnings("unchecked")
        ListResult<InformationLeakTest<PaddingOracleTestInfo>> listResult =
                (ListResult<InformationLeakTest<PaddingOracleTestInfo>>)
                        getListResult(TlsAnalyzedProperty.PADDING_ORACLE_TEST_RESULT);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<CertificateChain> getCertificateChainList() {
        @SuppressWarnings("unchecked")
        ListResult<CertificateChain> listResult =
                (ListResult<CertificateChain>)
                        getListResult(TlsAnalyzedProperty.CERTIFICATE_CHAINS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<VersionSuiteListPair> getVersionSuitePairs() {
        @SuppressWarnings("unchecked")
        ListResult<VersionSuiteListPair> listResult =
                (ListResult<VersionSuiteListPair>)
                        getListResult(TlsAnalyzedProperty.VERSION_SUITE_PAIRS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<ProtocolVersion> getSupportedProtocolVersions() {
        @SuppressWarnings("unchecked")
        ListResult<ProtocolVersion> listResult =
                (ListResult<ProtocolVersion>)
                        getListResult(TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS);
        return listResult == null ? null : listResult.getList();
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsCert() {
        @SuppressWarnings("unchecked")
        ListResult<SignatureAndHashAlgorithm> listResult =
                (ListResult<SignatureAndHashAlgorithm>)
                        getListResult(
                                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_CERT);
        return listResult == null ? null : listResult.getList();
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsSke() {
        @SuppressWarnings("unchecked")
        ListResult<SignatureAndHashAlgorithm> listResult =
                (ListResult<SignatureAndHashAlgorithm>)
                        getListResult(
                                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE);
        return listResult == null ? null : listResult.getList();
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsTls13() {
        @SuppressWarnings("unchecked")
        ListResult<SignatureAndHashAlgorithm> listResult =
                (ListResult<SignatureAndHashAlgorithm>)
                        getListResult(
                                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_TLS13);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
        if (getSupportedSignatureAndHashAlgorithmsCert() == null
                && getSupportedSignatureAndHashAlgorithmsSke() == null) {
            return null;
        }
        Set<SignatureAndHashAlgorithm> combined = new HashSet<>();
        if (getSupportedSignatureAndHashAlgorithmsCert() != null) {
            combined.addAll(getSupportedSignatureAndHashAlgorithmsCert());
        }
        if (getSupportedSignatureAndHashAlgorithmsSke() != null) {
            combined.addAll(getSupportedSignatureAndHashAlgorithmsSke());
        }
        return new LinkedList<>(combined);
    }

    public synchronized List<ExtensionType> getSupportedExtensions() {
        @SuppressWarnings("unchecked")
        ListResult<ExtensionType> listResult =
                (ListResult<ExtensionType>) getListResult(TlsAnalyzedProperty.SUPPORTED_EXTENSIONS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<CompressionMethod> getSupportedCompressionMethods() {
        @SuppressWarnings("unchecked")
        ListResult<CompressionMethod> listResult =
                (ListResult<CompressionMethod>)
                        getListResult(TlsAnalyzedProperty.SUPPORTED_COMPRESSION_METHODS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getSupportedTls13Groups() {
        @SuppressWarnings("unchecked")
        ListResult<NamedGroup> listResult =
                (ListResult<NamedGroup>) getListResult(TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getSupportedNamedGroups() {
        @SuppressWarnings("unchecked")
        ListResult<NamedGroup> listResult =
                (ListResult<NamedGroup>) getListResult(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getEphemeralEcdsaPkgGroups() {
        @SuppressWarnings("unchecked")
        ListResult<NamedGroup> listResult =
                (ListResult<NamedGroup>)
                        getListResult(TlsAnalyzedProperty.EPHEMERAL_ECDSA_PK_GROUPS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getTls13EcdsaPkgGroups() {
        @SuppressWarnings("unchecked")
        ListResult<NamedGroup> listResult =
                (ListResult<NamedGroup>) getListResult(TlsAnalyzedProperty.TLS13_ECDSA_PK_GROUPS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getStaticEcdsaSigGroups() {
        @SuppressWarnings("unchecked")
        ListResult<NamedGroup> listResult =
                (ListResult<NamedGroup>) getListResult(TlsAnalyzedProperty.STATIC_ECDSA_SIG_GROUPS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getEphemeralEcdsaSigGroups() {
        @SuppressWarnings("unchecked")
        ListResult<NamedGroup> listResult =
                (ListResult<NamedGroup>)
                        getListResult(TlsAnalyzedProperty.EPHEMERAL_ECDSA_SIG_GROUPS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getTls13EcdsaSigGroups() {
        @SuppressWarnings("unchecked")
        ListResult<NamedGroup> listResult =
                (ListResult<NamedGroup>) getListResult(TlsAnalyzedProperty.TLS13_ECDSA_SIG_GROUPS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<HttpHeader> getHttpHeader() {
        @SuppressWarnings("unchecked")
        ListResult<HttpHeader> listResult =
                (ListResult<HttpHeader>) getListResult(TlsAnalyzedProperty.HTTPS_HEADER);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<TokenBindingVersion> getSupportedTokenbindingVersions() {
        @SuppressWarnings("unchecked")
        ListResult<TokenBindingVersion> listResult =
                (ListResult<TokenBindingVersion>)
                        getListResult(TlsAnalyzedProperty.SUPPORTED_TOKENBINDING_VERSIONS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<TokenBindingKeyParameters> getSupportedTokenbindingKeyParameters() {
        @SuppressWarnings("unchecked")
        ListResult<TokenBindingKeyParameters> listResult =
                (ListResult<TokenBindingKeyParameters>)
                        getListResult(TlsAnalyzedProperty.SUPPORTED_TOKENBINDING_KEY_PARAMETERS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized Long getClosedAfterFinishedDelta() {
        return closedAfterFinishedDelta;
    }

    public synchronized void setClosedAfterFinishedDelta(Long closedAfterFinishedDelta) {
        this.closedAfterFinishedDelta = closedAfterFinishedDelta;
    }

    public synchronized Long getClosedAfterAppDataDelta() {
        return closedAfterAppDataDelta;
    }

    public synchronized void setClosedAfterAppDataDelta(Long closedAfterAppDataDelta) {
        this.closedAfterAppDataDelta = closedAfterAppDataDelta;
    }
}
