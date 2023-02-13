/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.result;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.probe.result.ProbeResult;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class CipherSuiteResult<Report extends TlsScanReport> extends ProbeResult<Report> {

    private List<VersionSuiteListPair> pairLists;

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

    public CipherSuiteResult(List<VersionSuiteListPair> pairLists) {
        super(TlsProbeType.CIPHER_SUITE);
        this.pairLists = pairLists;
    }

    @Override
    public void mergeData(TlsScanReport report) {
        if (pairLists != null) {
            Set<CipherSuite> allSupported = new HashSet<>();
            supportsOnlyPfsCiphers = TestResults.TRUE;
            prefersPfsCiphers = TestResults.TRUE;
            for (VersionSuiteListPair pair : pairLists) {
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
                    if (prfAlgorithm == PRFAlgorithm.TLS_PRF_LEGACY) {
                        supportsSha256Prf = TestResults.TRUE;
                    }
                    if (prfAlgorithm == PRFAlgorithm.TLS_PRF_LEGACY) {
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
            report.addCipherSuites(allSupported);
        } else {
            supportsAeadCiphers = TestResults.COULD_NOT_TEST;
            prefersPfsCiphers = TestResults.COULD_NOT_TEST;
            supportsAeadCiphers = TestResults.COULD_NOT_TEST;
            supportsAes = TestResults.COULD_NOT_TEST;
            supportsAnonCiphers = TestResults.COULD_NOT_TEST;
            supportsAria = TestResults.COULD_NOT_TEST;
            supportsBlockCiphers = TestResults.COULD_NOT_TEST;
            supportsCamellia = TestResults.COULD_NOT_TEST;
            supportsChacha = TestResults.COULD_NOT_TEST;
            supportsDesCiphers = TestResults.COULD_NOT_TEST;
            supportsDh = TestResults.COULD_NOT_TEST;
            supportsEcdhe = TestResults.COULD_NOT_TEST;
            supportsEcmqv = TestResults.COULD_NOT_TEST;
            supportsExportCiphers = TestResults.COULD_NOT_TEST;
            supportsFortezza = TestResults.COULD_NOT_TEST;
            supportsGost = TestResults.COULD_NOT_TEST;
            supportsIdeaCiphers = TestResults.COULD_NOT_TEST;
            supportsKerberos = TestResults.COULD_NOT_TEST;
            supportsNewHope = TestResults.COULD_NOT_TEST;
            supportsNullCiphers = TestResults.COULD_NOT_TEST;
            supportsOnlyPfsCiphers = TestResults.COULD_NOT_TEST;
            supportsPfsCiphers = TestResults.COULD_NOT_TEST;
            supportsPostQuantumCiphers = TestResults.COULD_NOT_TEST;
            supportsPskDhe = TestResults.COULD_NOT_TEST;
            supportsPskEcdhe = TestResults.COULD_NOT_TEST;
            supportsPskPlain = TestResults.COULD_NOT_TEST;
            supportsPskRsa = TestResults.COULD_NOT_TEST;
            supportsRc2Ciphers = TestResults.COULD_NOT_TEST;
            supportsRc4Ciphers = TestResults.COULD_NOT_TEST;
            supportsRsa = TestResults.COULD_NOT_TEST;
            supportsSeedCiphers = TestResults.COULD_NOT_TEST;
            supportsSrp = TestResults.COULD_NOT_TEST;
            supportsStaticEcdh = TestResults.COULD_NOT_TEST;
            supportsEcdsa = TestResults.COULD_NOT_TEST;
            supportsRsaCert = TestResults.COULD_NOT_TEST;
            supportsDss = TestResults.COULD_NOT_TEST;
            supportsStreamCiphers = TestResults.COULD_NOT_TEST;
            supportsTripleDesCiphers = TestResults.COULD_NOT_TEST;
            supportsLegacyPrf = TestResults.COULD_NOT_TEST;
            supportsSha256Prf = TestResults.COULD_NOT_TEST;
            supportsSha384Prf = TestResults.COULD_NOT_TEST;
        }
        writeToReport(report);
    }

    private void adjustCipherType(CipherSuite suite) {
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

    private void adjustKeyExchange(CipherSuite suite) {
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

    private void adjustBulk(CipherSuite suite) {
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

    private void adjustCertificate(CipherSuite suite) {
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

    private void writeToReport(TlsScanReport report) {
        report.putResult(TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS, supportsNullCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ANON, supportsAnonCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_EXPORT, supportsExportCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_DES, supportsDesCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SEED, supportsSeedCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_IDEA, supportsIdeaCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_RC2, supportsRc2Ciphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_RC4, supportsRc4Ciphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_3DES, supportsTripleDesCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_POST_QUANTUM, supportsPostQuantumCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_AEAD, supportsAeadCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_PFS, supportsPfsCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ONLY_PFS, supportsOnlyPfsCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_AES, supportsAes);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_CAMELLIA, supportsCamellia);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ARIA, supportsAria);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_CHACHA, supportsChacha);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_RSA, supportsRsa);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_STATIC_DH, supportsDh);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_DHE, supportsDhe);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH, supportsStaticEcdh);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ECDSA, supportsEcdsa);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_RSA_CERT, supportsRsaCert);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_DSS, supportsDss);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ECDHE, supportsEcdhe);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_GOST, supportsGost);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SRP, supportsSrp);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_KERBEROS, supportsKerberos);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN, supportsPskPlain);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_PSK_RSA, supportsPskRsa);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_PSK_DHE, supportsPskDhe);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE, supportsPskEcdhe);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_FORTEZZA, supportsFortezza);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_NEWHOPE, supportsNewHope);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_ECMQV, supportsEcmqv);
        report.putResult(TlsAnalyzedProperty.PREFERS_PFS, prefersPfsCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS, supportsStreamCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS, supportsBlockCiphers);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_LEGACY_PRF, supportsLegacyPrf);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SHA256_PRF, supportsSha256Prf);
        report.putResult(TlsAnalyzedProperty.SUPPORTS_SHA384_PRF, supportsSha384Prf);
        report.setVersionSuitePairs(pairLists);
    }
}
