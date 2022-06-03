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
import de.rub.nds.scanner.core.constants.SetResult;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@SuppressWarnings("unchecked")
public abstract class TlsReport extends ScanReport {

    private static final long serialVersionUID = 3589254912815026376L;

    @SuppressWarnings("rawtypes")
    public synchronized List getPaddingOracleTestResultList() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_PADDINGORACLE_TESTRESULT);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getClientSimulationResultList() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_CLIENT_SIMULATION_RESULTS);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getCertificateChainList() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_CERTIFICATE_CHAINS);
        return listResult == null ? null : listResult.getList();
    }

    @SuppressWarnings("rawtypes")
    public synchronized List getGuidelineReports() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_GUIDELINE_REPORTS);
        return listResult == null ? null : listResult.getList();
    }

    public synchronized Set<CipherSuite> getSupportedCipherSuites() {
        SetResult<?> setResult = getSetResult(TlsAnalyzedProperty.SET_SUPPORTED_CIPHERSUITES);
        return setResult == null ? null : (Set<CipherSuite>) setResult.getSet();
    }

    public synchronized List<VersionSuiteListPair> getVersionSuitePairs() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_VERSIONSUITE_PAIRS);
        return listResult == null ? null : (List<VersionSuiteListPair>) listResult.getList();
    }

    public synchronized List<ProtocolVersion> getSupportedProtocolVersions() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_SUPPORTED_PROTOCOLVERSIONS);
        return listResult == null ? null : (List<ProtocolVersion>) listResult.getList();
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsCert() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_CERT);
        return listResult == null ? null : (List<SignatureAndHashAlgorithm>) listResult.getList();
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithmsSke() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE);
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
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS);
        return listResult == null ? null : (List<ExtensionType>) listResult.getList();
    }

    public synchronized List<NamedGroup> getSupportedTls13Groups() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_SUPPORTED_TLS13_GROUPS);
        return listResult == null ? null : (List<NamedGroup>) listResult.getList();
    }

    public synchronized List<NamedGroup> getSupportedNamedGroups() {
        ListResult<?> listResult = getListResult(TlsAnalyzedProperty.LIST_SUPPORTED_NAMEDGROUPS);
        return listResult == null ? null : (List<NamedGroup>) listResult.getList();
    }
}
