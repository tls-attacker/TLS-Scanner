/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.report;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.constants.MapResult;
import de.rub.nds.scanner.core.constants.SetResult;
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
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@SuppressWarnings("unchecked")
public abstract class TlsReport extends ScanReport {

    private static final long serialVersionUID = 3589254912815026376L;

    @SuppressWarnings("rawtypes")
    public synchronized List getPaddingOracleTestResultList() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.PADDINGORACLE_TEST_RESULT);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getBleichenbacherTestResultList() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.BLEICHENBACHER_TEST_RESULT);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getRaccoonTestResultList() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.DIRECTRACCOON_TEST_RESULT);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getRaccoonAttackProbabilities() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.RACCOONATTACK_PROBABILITIES);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getInvalidCurveTestResultList() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.INVALIDCURVE_TEST_RESULT);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getCcaTestResultList() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.CCA_TEST_RESULTS);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getNormalHpkpPins() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.NORMAL_HPKPPINS);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getReportOnlyHpkpPins() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.REPORT_ONLY_HPKPPINS);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getClientSimulationResultList() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.CLIENT_SIMULATION_RESULTS);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getCertificateChainList() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.CERTIFICATE_CHAINS);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getGuidelineReports() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.GUIDELINE_REPORTS);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getSupportedApplicationProtocols() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_APPLICATIONS);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getEntropyReports() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.ENTROPY_REPORTS);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized Set getCommonDhValues() {
        SetResult<?> setResult = getSetResult(TlsAnalyzedProperty.COMMON_DH_VALUES);
        return setResult == null ? null : setResult.getSet();
    }

    @SuppressWarnings("rawtypes")
    public synchronized Map getSupportedNamedGroupsWitnesses() {
        MapResult<?, ?> mapResult = getMapResult(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES);
        return mapResult == null ? null : mapResult.getMap();
    }

    @SuppressWarnings("rawtypes")
    public synchronized Map getSupportedNamedGroupsWitnessesTls13() {
        MapResult<?, ?> mapResult = getMapResult(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES_TLS13);
        return mapResult == null ? null : mapResult.getMap();
    }

    public synchronized Map<HandshakeMessageType, Integer> getRetransmissionCounters() {
        MapResult<?, ?> mapResult = getMapResult(TlsAnalyzedProperty.MAP_RETRANSMISSION_COUNTERS);
        return mapResult == null ? null : (Map<HandshakeMessageType, Integer>) mapResult.getMap();
    }

    public synchronized Set<CipherSuite> getSupportedCipherSuites() {
        SetResult<?> setResult = getSetResult(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES);
        return setResult == null ? null : (Set<CipherSuite>) setResult.getSet();
    }

    public synchronized List<CipherSuite> getClientAdvertisedCiphersuites() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.CLIENT_ADVERTISED_CIPHERSUITES);
        return listResult == null ? null : (List<CipherSuite>) listResult.getList();
    }

    public synchronized List<VersionSuiteListPair> getVersionSuitePairs() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.VERSIONSUITE_PAIRS);
        return listResult == null ? null : (List<VersionSuiteListPair>) listResult.getList();
    }

    public synchronized List<ProtocolVersion> getSupportedProtocolVersions() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS);
        return listResult == null ? null : (List<ProtocolVersion>) listResult.getList();
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsCert() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_CERT);
        return listResult == null ? null : (List<SignatureAndHashAlgorithm>) listResult.getList();
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsSke() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE);
        return listResult == null ? null : (List<SignatureAndHashAlgorithm>) listResult.getList();
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsTls13() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_TLS13);
        return listResult == null ? null : (List<SignatureAndHashAlgorithm>) listResult.getList();
    }

    public synchronized List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
        HashSet<SignatureAndHashAlgorithm> combined = new HashSet<>();
        if (getSupportedSignatureAndHashAlgorithmsCert() != null) {
            combined.addAll(getSupportedSignatureAndHashAlgorithmsCert());
        }
        if (getSupportedSignatureAndHashAlgorithmsSke() != null) {
            combined.addAll(getSupportedSignatureAndHashAlgorithmsSke());
        }
        return new ArrayList<>(combined);
    }

    public synchronized List<ExtensionType> getSupportedExtensions() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_EXTENSIONS);
        return listResult == null ? null : (List<ExtensionType>) listResult.getList();
    }

    public synchronized List<CompressionMethod> getSupportedCompressionMethods() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_COMPRESSION_METHODS);
        return listResult == null ? null : (List<CompressionMethod>) listResult.getList();
    }

    public synchronized List<NamedGroup> getSupportedTls13Groups() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS);
        return listResult == null ? null : (List<NamedGroup>) listResult.getList();
    }

    public synchronized List<NamedGroup> getSupportedNamedGroups() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS);
        return listResult == null ? null : (List<NamedGroup>) listResult.getList();
    }

    public synchronized List<NamedGroup> getEphemeralEcdsaPkgGroups() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.EPHEMERAL_ECDSA_PKGROUPS);
        return listResult == null ? null : (List<NamedGroup>) listResult.getList();
    }

    public synchronized List<NamedGroup> getTls13EcdsaPkgGroups() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.TLS13_ECDSA_PKGROUPS);
        return listResult == null ? null : (List<NamedGroup>) listResult.getList();
    }

    public synchronized List<NamedGroup> getStaticEcdsaSigGroups() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.STATIC_ECDSA_SIGGROUPS);
        return listResult == null ? null : (List<NamedGroup>) listResult.getList();
    }

    public synchronized List<NamedGroup> getEphemeralEcdsaSigGroups() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.EPHEMERAL_ECDSA_SIGGROUPS);
        return listResult == null ? null : (List<NamedGroup>) listResult.getList();
    }

    public synchronized List<NamedGroup> getTls13EcdsaSigGroups() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.TLS13_ECDSA_SIGGROUPS);
        return listResult == null ? null : (List<NamedGroup>) listResult.getList();
    }

    public synchronized List<HttpsHeader> getHttpsHeader() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.HTTPS_HEADER);
        return listResult == null ? null : (List<HttpsHeader>) listResult.getList();
    }

    public synchronized List<TokenBindingVersion> getSupportedTokenbindingVersions() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_TOKENBINDING_VERSIONS);
        return listResult == null ? null : (List<TokenBindingVersion>) listResult.getList();
    }

    public synchronized List<TokenBindingKeyParameters> getSupportedTokenbindingKeyParameters() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.SUPPORTED_TOKENBINDING_KEYPARAMETERS);
        return listResult == null ? null : (List<TokenBindingKeyParameters>) listResult.getList();
    }

}
