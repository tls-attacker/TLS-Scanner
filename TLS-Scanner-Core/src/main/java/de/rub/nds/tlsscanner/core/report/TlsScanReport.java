/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.report;

import de.rub.nds.scanner.core.probe.result.IntegerResult;
import de.rub.nds.scanner.core.probe.result.ListResult;
import de.rub.nds.scanner.core.probe.result.MapResult;
import de.rub.nds.scanner.core.probe.result.ObjectResult;
import de.rub.nds.scanner.core.probe.result.SetResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.http.header.HttpHeader;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.leak.PaddingOracleTestInfo;
import de.rub.nds.tlsscanner.core.probe.certificate.CertificateChainReport;
import de.rub.nds.tlsscanner.core.probe.padding.KnownPaddingOracleVulnerability;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.vector.statistics.InformationLeakTest;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class TlsScanReport extends ScanReport {

    public TlsScanReport() {
        super();
    }

    public synchronized ProtocolType getProtocolType() {
        ObjectResult<ProtocolType> objectResult =
                getObjectResult(TlsAnalyzedProperty.PROTOCOL_TYPE, ProtocolType.class);
        return objectResult == null ? null : objectResult.getValue();
    }

    public synchronized KnownPaddingOracleVulnerability getKnownPaddingOracleVulnerability() {
        ObjectResult<KnownPaddingOracleVulnerability> objectResult =
                getObjectResult(
                        TlsAnalyzedProperty.KNOWN_PADDING_ORACLE_VULNERABILITY,
                        KnownPaddingOracleVulnerability.class);
        return objectResult == null ? null : objectResult.getValue();
    }

    public synchronized Integer getTotalReceivedRetransmissions() {
        IntegerResult integerResult =
                getIntegerResult(TlsAnalyzedProperty.TOTAL_RECEIVED_RETRANSMISSIONS);
        return integerResult == null ? null : integerResult.getValue();
    }

    public synchronized Boolean getCcaSupported() {
        return this.getResult(TlsAnalyzedProperty.SUPPORTS_CCA) == TestResults.TRUE;
    }

    public synchronized Boolean getCcaRequired() {
        return this.getResult(TlsAnalyzedProperty.REQUIRES_CCA) == TestResults.TRUE;
    }

    public synchronized Map<HandshakeMessageType, Integer> getRetransmissionCounters() {
        MapResult<HandshakeMessageType, Integer> mapResult =
                getMapResult(
                        TlsAnalyzedProperty.MAP_RETRANSMISSION_COUNTERS,
                        HandshakeMessageType.class,
                        Integer.class);
        return mapResult == null ? null : mapResult.getMap();
    }

    public synchronized Set<CipherSuite> getSupportedCipherSuites() {
        SetResult<CipherSuite> setResult =
                getSetResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES, CipherSuite.class);
        return setResult == null ? null : setResult.getSet();
    }

    public synchronized List<EntropyReport> getEntropyReports() {
        ListResult<EntropyReport> listResult =
                getListResult(TlsAnalyzedProperty.ENTROPY_REPORTS, EntropyReport.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<InformationLeakTest<PaddingOracleTestInfo>>
            getPaddingOracleTestResultList() {
        ListResult<InformationLeakTest<PaddingOracleTestInfo>> listResult =
                (ListResult<InformationLeakTest<PaddingOracleTestInfo>>)
                        getListResult(TlsAnalyzedProperty.PADDING_ORACLE_TEST_RESULT);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<CertificateChainReport> getCertificateChainList() {
        ListResult<CertificateChainReport> listResult =
                (ListResult<CertificateChainReport>)
                        getListResult(
                                TlsAnalyzedProperty.CERTIFICATE_CHAINS,
                                CertificateChainReport.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<VersionSuiteListPair> getVersionSuitePairs() {
        ListResult<VersionSuiteListPair> listResult =
                getListResult(TlsAnalyzedProperty.VERSION_SUITE_PAIRS, VersionSuiteListPair.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<ProtocolVersion> getSupportedProtocolVersions() {
        ListResult<ProtocolVersion> listResult =
                getListResult(
                        TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS, ProtocolVersion.class);
        return listResult == null ? null : listResult.getList();
    }

    public List<X509SignatureAlgorithm> getSupportedCertSignatureAlgorithms() {
        ListResult<X509SignatureAlgorithm> listResult =
                getListResult(
                        TlsAnalyzedProperty.SUPPORTED_CERT_SIGNATURE_ALGORITHMS,
                        X509SignatureAlgorithm.class);
        return listResult == null ? null : listResult.getList();
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsSke() {
        ListResult<SignatureAndHashAlgorithm> listResult =
                getListResult(
                        TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE,
                        SignatureAndHashAlgorithm.class);
        return listResult == null ? null : listResult.getList();
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsTls13() {
        ListResult<SignatureAndHashAlgorithm> listResult =
                getListResult(
                        TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_TLS13,
                        SignatureAndHashAlgorithm.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
        if (getSupportedCertSignatureAlgorithms() == null
                && getSupportedSignatureAndHashAlgorithmsSke() == null) {
            return null;
        }
        return getSupportedSignatureAndHashAlgorithmsSke();
    }

    public synchronized List<ExtensionType> getSupportedExtensions() {
        ListResult<ExtensionType> listResult =
                getListResult(TlsAnalyzedProperty.SUPPORTED_EXTENSIONS, ExtensionType.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<CompressionMethod> getSupportedCompressionMethods() {
        ListResult<CompressionMethod> listResult =
                getListResult(
                        TlsAnalyzedProperty.SUPPORTED_COMPRESSION_METHODS, CompressionMethod.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getSupportedTls13Groups() {
        ListResult<NamedGroup> listResult =
                getListResult(TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS, NamedGroup.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getSupportedNamedGroups() {
        ListResult<NamedGroup> listResult =
                getListResult(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS, NamedGroup.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getStaticEcdsaPkgGroups() {
        ListResult<NamedGroup> listResult =
                getListResult(TlsAnalyzedProperty.STATIC_ECDSA_PK_GROUPS, NamedGroup.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getEphemeralEcdsaPkgGroups() {
        ListResult<NamedGroup> listResult =
                getListResult(TlsAnalyzedProperty.EPHEMERAL_ECDSA_PK_GROUPS, NamedGroup.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getTls13EcdsaPkgGroups() {
        ListResult<NamedGroup> listResult =
                getListResult(TlsAnalyzedProperty.TLS13_ECDSA_PK_GROUPS, NamedGroup.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getStaticEcdsaSigGroups() {
        ListResult<NamedGroup> listResult =
                getListResult(TlsAnalyzedProperty.STATIC_ECDSA_SIG_GROUPS, NamedGroup.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getEphemeralEcdsaSigGroups() {
        ListResult<NamedGroup> listResult =
                getListResult(TlsAnalyzedProperty.EPHEMERAL_ECDSA_SIG_GROUPS, NamedGroup.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<NamedGroup> getTls13EcdsaSigGroups() {
        ListResult<NamedGroup> listResult =
                getListResult(TlsAnalyzedProperty.TLS13_ECDSA_SIG_GROUPS, NamedGroup.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<HttpHeader> getHttpHeader() {
        ListResult<HttpHeader> listResult =
                getListResult(TlsAnalyzedProperty.HTTPS_HEADER, HttpHeader.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<TokenBindingVersion> getSupportedTokenbindingVersions() {
        ListResult<TokenBindingVersion> listResult =
                getListResult(
                        TlsAnalyzedProperty.SUPPORTED_TOKENBINDING_VERSIONS,
                        TokenBindingVersion.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<TokenBindingKeyParameters> getSupportedTokenbindingKeyParameters() {
        ListResult<TokenBindingKeyParameters> listResult =
                getListResult(
                        TlsAnalyzedProperty.SUPPORTED_TOKENBINDING_KEY_PARAMETERS,
                        TokenBindingKeyParameters.class);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized List<String> getSupportedAlpnConstans() {
        ListResult<String> listResult =
                getListResult(TlsAnalyzedProperty.SUPPORTED_ALPN_CONSTANTS, String.class);
        return listResult == null ? null : listResult.getList();
    }

    public List<CipherSuite> getSupportedCipherSuitesWithKeyExchange(
            KeyExchangeAlgorithm... algorithms) {
        Set<CipherSuite> cipherSuites = getSupportedCipherSuites();
        List<KeyExchangeAlgorithm> matchingKeyExchangeAlgorithms = Arrays.asList(algorithms);
        if (cipherSuites == null) {
            return new LinkedList<>();
        } else {
            return cipherSuites.stream()
                    .filter(
                            cipherSuite ->
                                    matchingKeyExchangeAlgorithms.contains(
                                            AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)))
                    .collect(Collectors.toList());
        }
    }
}
