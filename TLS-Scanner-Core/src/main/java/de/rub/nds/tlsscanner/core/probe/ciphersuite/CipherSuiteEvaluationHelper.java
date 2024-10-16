/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.ciphersuite;

import de.rub.nds.scanner.core.probe.result.TestResult;
import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.config.TlsScannerConfig;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.probe.TlsProbe;
import de.rub.nds.tlsscanner.core.probe.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class CipherSuiteEvaluationHelper {

    private final List<ProtocolVersion> protocolVersions;

    private List<VersionSuiteListPair> pairLists = null;

    private TestResult supportsNullCiphers = TestResults.FALSE;
    private TestResult supportsAnonCiphers = TestResults.FALSE;
    private TestResult supportsExportCiphers = TestResults.FALSE;
    private TestResult supportsDesCiphers = TestResults.FALSE;
    private TestResult supportsSeedCiphers = TestResults.FALSE;
    private TestResult supportsIdeaCiphers = TestResults.FALSE;
    private TestResult supportsRc2Ciphers = TestResults.FALSE;
    private TestResult supportsRc4Ciphers = TestResults.FALSE;
    private TestResult supportsTripleDesCiphers = TestResults.FALSE;
    private TestResult supportsPostQuantumCiphers = TestResults.FALSE;
    private TestResult supportsAeadCiphers = TestResults.FALSE;
    private TestResult supportsPfsCiphers = TestResults.FALSE;
    private TestResult supportsOnlyPfsCiphers = TestResults.FALSE;
    private TestResult supportsAes = TestResults.FALSE;
    private TestResult supportsCamellia = TestResults.FALSE;
    private TestResult supportsAria = TestResults.FALSE;
    private TestResult supportsChacha = TestResults.FALSE;
    private TestResult supportsRsa = TestResults.FALSE;
    private TestResult supportsRsaSig = TestResults.FALSE;
    private TestResult supportsDh = TestResults.FALSE;
    private TestResult supportsDhe = TestResults.FALSE;
    private TestResult supportsEcdhe = TestResults.FALSE;
    private TestResult supportsStaticEcdh = TestResults.FALSE;
    private TestResult supportsEcdsa = TestResults.FALSE;
    private TestResult supportsRsaCert = TestResults.FALSE;
    private TestResult supportsDss = TestResults.FALSE;
    private TestResult supportsGost = TestResults.FALSE;
    private TestResult supportsSrp = TestResults.FALSE;
    private TestResult supportsKerberos = TestResults.FALSE;
    private TestResult supportsPskPlain = TestResults.FALSE;
    private TestResult supportsPskRsa = TestResults.FALSE;
    private TestResult supportsPskDhe = TestResults.FALSE;
    private TestResult supportsPskEcdhe = TestResults.FALSE;
    private TestResult supportsFortezza = TestResults.FALSE;
    private TestResult supportsNewHope = TestResults.FALSE;
    private TestResult supportsEcmqv = TestResults.FALSE;
    private TestResult prefersPfsCiphers = TestResults.FALSE;
    private TestResult supportsStreamCiphers = TestResults.FALSE;
    private TestResult supportsBlockCiphers = TestResults.FALSE;
    private TestResult supportsLegacyPrf = TestResults.FALSE;
    private TestResult supportsSha256Prf = TestResults.FALSE;
    private TestResult supportsSha384Prf = TestResults.FALSE;

    public CipherSuiteEvaluationHelper(List<ProtocolVersion> protocolVersions) {
        this.protocolVersions = protocolVersions;
    }

    public static TlsAnalyzedProperty[] getProperties() {
        return new TlsAnalyzedProperty[] {
            TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS,
            TlsAnalyzedProperty.SUPPORTS_ANON,
            TlsAnalyzedProperty.SUPPORTS_EXPORT,
            TlsAnalyzedProperty.SUPPORTS_DES,
            TlsAnalyzedProperty.SUPPORTS_SEED,
            TlsAnalyzedProperty.SUPPORTS_IDEA,
            TlsAnalyzedProperty.SUPPORTS_RC2,
            TlsAnalyzedProperty.SUPPORTS_RC4,
            TlsAnalyzedProperty.SUPPORTS_3DES,
            TlsAnalyzedProperty.SUPPORTS_POST_QUANTUM,
            TlsAnalyzedProperty.SUPPORTS_AEAD,
            TlsAnalyzedProperty.SUPPORTS_PFS,
            TlsAnalyzedProperty.SUPPORTS_ONLY_PFS,
            TlsAnalyzedProperty.SUPPORTS_AES,
            TlsAnalyzedProperty.SUPPORTS_CAMELLIA,
            TlsAnalyzedProperty.SUPPORTS_ARIA,
            TlsAnalyzedProperty.SUPPORTS_CHACHA,
            TlsAnalyzedProperty.SUPPORTS_RSA,
            TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH,
            TlsAnalyzedProperty.SUPPORTS_ECDSA,
            TlsAnalyzedProperty.SUPPORTS_RSA_CERT,
            TlsAnalyzedProperty.SUPPORTS_RSA_SIG,
            TlsAnalyzedProperty.SUPPORTS_DSS,
            TlsAnalyzedProperty.SUPPORTS_GOST,
            TlsAnalyzedProperty.SUPPORTS_SRP,
            TlsAnalyzedProperty.SUPPORTS_KERBEROS,
            TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN,
            TlsAnalyzedProperty.SUPPORTS_PSK_RSA,
            TlsAnalyzedProperty.SUPPORTS_PSK_DHE,
            TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE,
            TlsAnalyzedProperty.SUPPORTS_FORTEZZA,
            TlsAnalyzedProperty.SUPPORTS_NEWHOPE,
            TlsAnalyzedProperty.SUPPORTS_ECMQV,
            TlsAnalyzedProperty.PREFERS_PFS,
            TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS,
            TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS,
            TlsAnalyzedProperty.SUPPORTS_LEGACY_PRF,
            TlsAnalyzedProperty.SUPPORTS_SHA256_PRF,
            TlsAnalyzedProperty.SUPPORTS_SHA384_PRF,
            TlsAnalyzedProperty.VERSION_SUITE_PAIRS,
            TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES,
            TlsAnalyzedProperty.SUPPORTS_ECDHE,
            TlsAnalyzedProperty.SUPPORTS_DHE,
            TlsAnalyzedProperty.SUPPORTS_STATIC_DH
        };
    }

    @SuppressWarnings("unchecked")
    public List<CipherSuite> getToTestCipherSuitesByVersion(
            ProtocolVersion version, TlsScannerConfig scannerConfig) {
        if (version == ProtocolVersion.SSL3) {
            return (List<CipherSuite>) CipherSuite.SSL3_SUPPORTED_CIPHERSUITES;
        }
        if (version == ProtocolVersion.TLS13) {
            return CipherSuite.getImplementedTls13CipherSuites();
        }
        List<CipherSuite> realCipherSuites =
                Arrays.asList(CipherSuite.values()).stream()
                        .filter(suite -> suite.isRealCipherSuite())
                        .collect(Collectors.toList());
        switch (scannerConfig.getExecutorConfig().getScanDetail()) {
            case QUICK:
            case NORMAL:
                return filterPskCipherSuites(filterForVersionSupported(realCipherSuites, version));
            case DETAILED:
                return filterForVersionSupported(realCipherSuites, version);
            case ALL:
            default:
                return realCipherSuites;
        }
    }

    public List<CipherSuite> filterForVersionSupported(
            Collection<CipherSuite> suites, ProtocolVersion version) {
        return suites.stream()
                .filter(suite -> suite.isSupportedInProtocol(version))
                .collect(Collectors.toList());
    }

    public List<CipherSuite> filterPskCipherSuites(Collection<CipherSuite> suites) {
        return suites.stream().filter(suite -> !suite.isPsk()).collect(Collectors.toList());
    }

    public void mergeData(TlsScanReport report, TlsProbe probe) {
        if (getPairLists() != null) {
            Set<CipherSuite> allSupported = new HashSet<>();
            supportsOnlyPfsCiphers = TestResults.TRUE;
            prefersPfsCiphers = TestResults.TRUE;
            for (VersionSuiteListPair pair : getPairLists()) {
                if (pair.getCipherSuiteList().size() > 0
                        && !pair.getCipherSuiteList().get(0).isEphemeral()) {
                    prefersPfsCiphers = TestResults.FALSE;
                }
                allSupported.addAll(pair.getCipherSuiteList());
                for (CipherSuite suite : pair.getCipherSuiteList()) {
                    PRFAlgorithm prfAlgorithm =
                            AlgorithmResolver.getPRFAlgorithm(pair.getVersion(), suite);
                    if (prfAlgorithm == PRFAlgorithm.TLS_PRF_LEGACY) {
                        supportsLegacyPrf = TestResults.TRUE;
                    }
                    if (prfAlgorithm == PRFAlgorithm.TLS_PRF_SHA256) {
                        supportsSha256Prf = TestResults.TRUE;
                    }
                    if (prfAlgorithm == PRFAlgorithm.TLS_PRF_SHA384) {
                        supportsSha384Prf = TestResults.TRUE;
                    }
                }
            }
            for (CipherSuite suite : allSupported) {
                adjustBulk(suite);
                adjustKeyExchange(suite);
                adjustCipherType(suite);
                adjustCertificate(suite);
            }
            probe.put(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES, allSupported);
            writeToReport(probe);
        } else {
            probe.put(TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES, Collections.emptySet());
            probe.setPropertiesToCouldNotTest();
        }
    }

    public void adjustCipherType(CipherSuite suite) {
        CipherType cipherType = AlgorithmResolver.getCipherType(suite);
        switch (cipherType) {
            case AEAD:
                supportsAeadCiphers = TestResults.TRUE;
                break;
            case BLOCK:
                supportsBlockCiphers = TestResults.TRUE;
                break;
            case STREAM:
                supportsStreamCiphers = TestResults.TRUE;
                break;
            default:
                ;
        }
    }

    public void adjustKeyExchange(CipherSuite suite) {
        if (suite.name().contains("SRP")) {
            supportsSrp = TestResults.TRUE;
        }
        if (suite.name().contains("_DH_")) {
            supportsDh = TestResults.TRUE;
        }
        if (suite.name().contains("_DHE_")) {
            supportsDhe = TestResults.TRUE;
        }
        if (suite.name().contains("TLS_RSA")) {
            supportsRsa = TestResults.TRUE;
        }
        if (suite.name().contains("_RSA")) {
            supportsRsaSig = TestResults.TRUE;
        }
        if (suite.name().contains("ECDH_")) {
            supportsStaticEcdh = TestResults.TRUE;
        }
        if (suite.name().contains("ECDH")) {
            supportsEcdhe = TestResults.TRUE;
        }
        if (suite.name().contains("NULL")) {
            supportsNullCiphers = TestResults.TRUE;
        }
        if (suite.name().contains("GOST")) {
            supportsGost = TestResults.TRUE;
        }
        if (suite.name().contains("KRB5")) {
            supportsKerberos = TestResults.TRUE;
        }
        if (suite.name().contains("TLS_PSK_WITH")) {
            supportsPskPlain = TestResults.TRUE;
        }
        if (suite.name().contains("_DHE_PSK")) {
            supportsPskDhe = TestResults.TRUE;
        }
        if (suite.name().contains("ECDHE_PSK")) {
            supportsPskEcdhe = TestResults.TRUE;
        }
        if (suite.name().contains("RSA_PSK")) {
            supportsPskRsa = TestResults.TRUE;
        }
        if (suite.name().contains("FORTEZZA")) {
            supportsFortezza = TestResults.TRUE;
        }
        if (suite.name().contains("ECMQV")) {
            supportsPostQuantumCiphers = TestResults.TRUE;
            supportsEcmqv = TestResults.TRUE;
        }
        if (suite.name().contains("CECPQ1")) {
            supportsPostQuantumCiphers = TestResults.TRUE;
            supportsNewHope = TestResults.TRUE;
        }
        if (suite.name().contains("anon")) {
            supportsAnonCiphers = TestResults.TRUE;
        }
        if (suite.isEphemeral()) {
            supportsPfsCiphers = TestResults.TRUE;
        } else {
            supportsOnlyPfsCiphers = TestResults.FALSE;
        }
        if (suite.isExport()) {
            supportsExportCiphers = TestResults.TRUE;
        }
    }

    public void adjustBulk(CipherSuite suite) {
        BulkCipherAlgorithm bulkCipherAlgorithm = AlgorithmResolver.getBulkCipherAlgorithm(suite);
        switch (bulkCipherAlgorithm) {
            case AES:
                supportsAes = TestResults.TRUE;
                break;
            case CAMELLIA:
                supportsCamellia = TestResults.TRUE;
                break;
            case DES40:
                supportsDesCiphers = TestResults.TRUE;
                supportsExportCiphers = TestResults.TRUE;
                break;
            case DES:
                supportsDesCiphers = TestResults.TRUE;
                break;
            case ARIA:
                supportsAria = TestResults.TRUE;
                break;
            case DESede:
                supportsTripleDesCiphers = TestResults.TRUE;
                break;
            case FORTEZZA:
                supportsFortezza = TestResults.TRUE;
                break;
            case IDEA:
                supportsIdeaCiphers = TestResults.TRUE;
                break;
            case NULL:
                supportsNullCiphers = TestResults.TRUE;
                break;
            case RC2:
                supportsRc2Ciphers = TestResults.TRUE;
                break;
            case RC4:
                supportsRc4Ciphers = TestResults.TRUE;
                break;
            case SEED:
                supportsSeedCiphers = TestResults.TRUE;
                break;
            case CHACHA20_POLY1305:
                supportsChacha = TestResults.TRUE;
                break;
            default:
                ;
        }
    }

    public void adjustCertificate(CipherSuite suite) {
        if (suite.name().contains("ECDSA")) {
            supportsEcdsa = TestResults.TRUE;
        }
        if (suite.name().contains("DSS")) {
            supportsDss = TestResults.TRUE;
        }
        if (suite.name().contains("RSA")) {
            supportsRsaCert = TestResults.TRUE;
        }
    }

    public void writeToReport(TlsProbe probe) {
        probe.put(TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS, supportsNullCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_ANON, supportsAnonCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_EXPORT, supportsExportCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_DES, supportsDesCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_SEED, supportsSeedCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_IDEA, supportsIdeaCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_RC2, supportsRc2Ciphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_RC4, supportsRc4Ciphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_3DES, supportsTripleDesCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_POST_QUANTUM, supportsPostQuantumCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_AEAD, supportsAeadCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_PFS, supportsPfsCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_ONLY_PFS, supportsOnlyPfsCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_AES, supportsAes);
        probe.put(TlsAnalyzedProperty.SUPPORTS_CAMELLIA, supportsCamellia);
        probe.put(TlsAnalyzedProperty.SUPPORTS_ARIA, supportsAria);
        probe.put(TlsAnalyzedProperty.SUPPORTS_CHACHA, supportsChacha);
        probe.put(TlsAnalyzedProperty.SUPPORTS_RSA, supportsRsa);
        probe.put(TlsAnalyzedProperty.SUPPORTS_RSA_SIG, supportsRsaSig);
        probe.put(TlsAnalyzedProperty.SUPPORTS_STATIC_DH, supportsDh);
        probe.put(TlsAnalyzedProperty.SUPPORTS_DHE, supportsDhe);
        probe.put(TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH, supportsStaticEcdh);
        probe.put(TlsAnalyzedProperty.SUPPORTS_ECDSA, supportsEcdsa);
        probe.put(TlsAnalyzedProperty.SUPPORTS_RSA_CERT, supportsRsaCert);
        probe.put(TlsAnalyzedProperty.SUPPORTS_DSS, supportsDss);
        probe.put(TlsAnalyzedProperty.SUPPORTS_ECDHE, supportsEcdhe);
        probe.put(TlsAnalyzedProperty.SUPPORTS_GOST, supportsGost);
        probe.put(TlsAnalyzedProperty.SUPPORTS_SRP, supportsSrp);
        probe.put(TlsAnalyzedProperty.SUPPORTS_KERBEROS, supportsKerberos);
        probe.put(TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN, supportsPskPlain);
        probe.put(TlsAnalyzedProperty.SUPPORTS_PSK_RSA, supportsPskRsa);
        probe.put(TlsAnalyzedProperty.SUPPORTS_PSK_DHE, supportsPskDhe);
        probe.put(TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE, supportsPskEcdhe);
        probe.put(TlsAnalyzedProperty.SUPPORTS_FORTEZZA, supportsFortezza);
        probe.put(TlsAnalyzedProperty.SUPPORTS_NEWHOPE, supportsNewHope);
        probe.put(TlsAnalyzedProperty.SUPPORTS_ECMQV, supportsEcmqv);
        probe.put(TlsAnalyzedProperty.PREFERS_PFS, prefersPfsCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS, supportsStreamCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS, supportsBlockCiphers);
        probe.put(TlsAnalyzedProperty.SUPPORTS_LEGACY_PRF, supportsLegacyPrf);
        probe.put(TlsAnalyzedProperty.SUPPORTS_SHA256_PRF, supportsSha256Prf);
        probe.put(TlsAnalyzedProperty.SUPPORTS_SHA384_PRF, supportsSha384Prf);
        probe.put(TlsAnalyzedProperty.VERSION_SUITE_PAIRS, getPairLists());
    }

    public void configureVersions(TlsScanReport report) {
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_0) == TestResults.TRUE) {
            getProtocolVersions().add(ProtocolVersion.DTLS10);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_DTLS_1_2) == TestResults.TRUE) {
            getProtocolVersions().add(ProtocolVersion.DTLS12);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_SSL_3) == TestResults.TRUE) {
            getProtocolVersions().add(ProtocolVersion.SSL3);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_0) == TestResults.TRUE) {
            getProtocolVersions().add(ProtocolVersion.TLS10);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_1) == TestResults.TRUE) {
            getProtocolVersions().add(ProtocolVersion.TLS11);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_2) == TestResults.TRUE) {
            getProtocolVersions().add(ProtocolVersion.TLS12);
        }
        if (report.getResult(TlsAnalyzedProperty.SUPPORTS_TLS_1_3) == TestResults.TRUE) {
            getProtocolVersions().add(ProtocolVersion.TLS13);
        }
    }

    public List<ProtocolVersion> getProtocolVersions() {
        return protocolVersions;
    }

    public List<VersionSuiteListPair> getPairLists() {
        return pairLists;
    }

    public void setPairLists(List<VersionSuiteListPair> pairLists) {
        this.pairLists = pairLists;
    }
}
