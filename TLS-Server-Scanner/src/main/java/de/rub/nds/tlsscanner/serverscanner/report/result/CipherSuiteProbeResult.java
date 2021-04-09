/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class CipherSuiteProbeResult extends ProbeResult {

    private List<VersionSuiteListPair> pairLists;

    private TestResult supportsNullCiphers = TestResult.FALSE;
    private TestResult supportsAnonCiphers = TestResult.FALSE;
    private TestResult supportsExportCiphers = TestResult.FALSE;
    private TestResult supportsDesCiphers = TestResult.FALSE;
    private TestResult supportsSeedCiphers = TestResult.FALSE;
    private TestResult supportsIdeaCiphers = TestResult.FALSE;
    private TestResult supportsRc2Ciphers = TestResult.FALSE;
    private TestResult supportsRc4Ciphers = TestResult.FALSE;
    private TestResult supportsTripleDesCiphers = TestResult.FALSE;
    private TestResult supportsPostQuantumCiphers = TestResult.FALSE;
    private TestResult supportsAeadCiphers = TestResult.FALSE;
    private TestResult supportsPfsCiphers = TestResult.FALSE;
    private TestResult supportsOnlyPfsCiphers = TestResult.FALSE;
    private TestResult supportsAes = TestResult.FALSE;
    private TestResult supportsCamellia = TestResult.FALSE;
    private TestResult supportsAria = TestResult.FALSE;
    private TestResult supportsChacha = TestResult.FALSE;
    private TestResult supportsRsa = TestResult.FALSE;
    private TestResult supportsDh = TestResult.FALSE;
    private TestResult supportsEcdh = TestResult.FALSE;
    private TestResult supportsStaticEcdh = TestResult.FALSE;
    private TestResult supportsEcdsa = TestResult.FALSE;
    private TestResult supportsRsaCert = TestResult.FALSE;
    private TestResult supportsDss = TestResult.FALSE;
    private TestResult supportsGost = TestResult.FALSE;
    private TestResult supportsSrp = TestResult.FALSE;
    private TestResult supportsKerberos = TestResult.FALSE;
    private TestResult supportsPskPlain = TestResult.FALSE;
    private TestResult supportsPskRsa = TestResult.FALSE;
    private TestResult supportsPskDhe = TestResult.FALSE;
    private TestResult supportsPskEcdhe = TestResult.FALSE;
    private TestResult supportsFortezza = TestResult.FALSE;
    private TestResult supportsNewHope = TestResult.FALSE;
    private TestResult supportsEcmqv = TestResult.FALSE;
    private TestResult prefersPfsCiphers = TestResult.FALSE;
    private TestResult supportsStreamCiphers = TestResult.FALSE;
    private TestResult supportsBlockCiphers = TestResult.FALSE;
    private TestResult supportsLegacyPrf = TestResult.FALSE;
    private TestResult supportsSha256Prf = TestResult.FALSE;
    private TestResult supportsSha384Prf = TestResult.FALSE;

    public CipherSuiteProbeResult(List<VersionSuiteListPair> pairLists) {
        super(ProbeType.CIPHER_SUITE);
        this.pairLists = pairLists;
    }

    @Override
    public void mergeData(SiteReport report) {
        if (pairLists != null) {
            Set<CipherSuite> allSupported = new HashSet<>();
            supportsOnlyPfsCiphers = TestResult.TRUE;
            prefersPfsCiphers = TestResult.TRUE;
            for (VersionSuiteListPair pair : pairLists) {
                if (pair.getCipherSuiteList().size() > 0 && !pair.getCipherSuiteList().get(0).isEphemeral()) {
                    prefersPfsCiphers = TestResult.FALSE;
                }
                allSupported.addAll(pair.getCipherSuiteList());

                for (CipherSuite suite : pair.getCipherSuiteList()) {
                    PRFAlgorithm prfAlgorithm = AlgorithmResolver.getPRFAlgorithm(pair.getVersion(), suite);
                    if (prfAlgorithm == PRFAlgorithm.TLS_PRF_LEGACY) {
                        supportsLegacyPrf = TestResult.TRUE;
                    }
                    if (prfAlgorithm == PRFAlgorithm.TLS_PRF_LEGACY) {
                        supportsSha256Prf = TestResult.TRUE;
                    }
                    if (prfAlgorithm == PRFAlgorithm.TLS_PRF_LEGACY) {
                        supportsSha384Prf = TestResult.TRUE;
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
            supportsAeadCiphers = TestResult.COULD_NOT_TEST;
            prefersPfsCiphers = TestResult.COULD_NOT_TEST;
            supportsAeadCiphers = TestResult.COULD_NOT_TEST;
            supportsAes = TestResult.COULD_NOT_TEST;
            supportsAnonCiphers = TestResult.COULD_NOT_TEST;
            supportsAria = TestResult.COULD_NOT_TEST;
            supportsBlockCiphers = TestResult.COULD_NOT_TEST;
            supportsCamellia = TestResult.COULD_NOT_TEST;
            supportsChacha = TestResult.COULD_NOT_TEST;
            supportsDesCiphers = TestResult.COULD_NOT_TEST;
            supportsDh = TestResult.COULD_NOT_TEST;
            supportsEcdh = TestResult.COULD_NOT_TEST;
            supportsEcmqv = TestResult.COULD_NOT_TEST;
            supportsExportCiphers = TestResult.COULD_NOT_TEST;
            supportsFortezza = TestResult.COULD_NOT_TEST;
            supportsGost = TestResult.COULD_NOT_TEST;
            supportsIdeaCiphers = TestResult.COULD_NOT_TEST;
            supportsKerberos = TestResult.COULD_NOT_TEST;
            supportsNewHope = TestResult.COULD_NOT_TEST;
            supportsNullCiphers = TestResult.COULD_NOT_TEST;
            supportsOnlyPfsCiphers = TestResult.COULD_NOT_TEST;
            supportsPfsCiphers = TestResult.COULD_NOT_TEST;
            supportsPostQuantumCiphers = TestResult.COULD_NOT_TEST;
            supportsPskDhe = TestResult.COULD_NOT_TEST;
            supportsPskEcdhe = TestResult.COULD_NOT_TEST;
            supportsPskPlain = TestResult.COULD_NOT_TEST;
            supportsPskRsa = TestResult.COULD_NOT_TEST;
            supportsRc2Ciphers = TestResult.COULD_NOT_TEST;
            supportsRc4Ciphers = TestResult.COULD_NOT_TEST;
            supportsRsa = TestResult.COULD_NOT_TEST;
            supportsSeedCiphers = TestResult.COULD_NOT_TEST;
            supportsSrp = TestResult.COULD_NOT_TEST;
            supportsStaticEcdh = TestResult.COULD_NOT_TEST;
            supportsEcdsa = TestResult.COULD_NOT_TEST;
            supportsRsaCert = TestResult.COULD_NOT_TEST;
            supportsDss = TestResult.COULD_NOT_TEST;
            supportsStreamCiphers = TestResult.COULD_NOT_TEST;
            supportsTripleDesCiphers = TestResult.COULD_NOT_TEST;
            supportsLegacyPrf = TestResult.COULD_NOT_TEST;
            supportsSha256Prf = TestResult.COULD_NOT_TEST;
            supportsSha384Prf = TestResult.COULD_NOT_TEST;
        }
        writeToReport(report);
    }

    private void adjustCipherType(CipherSuite suite) {
        CipherType cipherType = AlgorithmResolver.getCipherType(suite);
        switch (cipherType) {
            case AEAD:
                supportsAeadCiphers = TestResult.TRUE;
                break;
            case BLOCK:
                supportsBlockCiphers = TestResult.TRUE;
                break;
            case STREAM:
                supportsStreamCiphers = TestResult.TRUE;
                break;
            default:
                ;
        }
    }

    private void adjustKeyExchange(CipherSuite suite) {
        if (suite.name().contains("SRP")) {
            supportsSrp = TestResult.TRUE;
        }
        if (suite.name().contains("_DH")) {
            supportsDh = TestResult.TRUE;
        }
        if (suite.name().contains("TLS_RSA")) {
            supportsRsa = TestResult.TRUE;
        }
        if (suite.name().contains("ECDH_")) {
            supportsStaticEcdh = TestResult.TRUE;
        }
        if (suite.name().contains("ECDH")) {
            supportsEcdh = TestResult.TRUE;
        }
        if (suite.name().contains("NULL")) {
            supportsNullCiphers = TestResult.TRUE;
        }
        if (suite.name().contains("GOST")) {
            supportsGost = TestResult.TRUE;
        }
        if (suite.name().contains("KRB5")) {
            supportsKerberos = TestResult.TRUE;
        }
        if (suite.name().contains("TLS_PSK_WITH")) {
            supportsPskPlain = TestResult.TRUE;
        }
        if (suite.name().contains("_DHE_PSK")) {
            supportsPskDhe = TestResult.TRUE;
        }
        if (suite.name().contains("ECDHE_PSK")) {
            supportsPskEcdhe = TestResult.TRUE;
        }
        if (suite.name().contains("RSA_PSK")) {
            supportsPskRsa = TestResult.TRUE;
        }
        if (suite.name().contains("FORTEZZA")) {
            supportsFortezza = TestResult.TRUE;
        }
        if (suite.name().contains("ECMQV")) {
            supportsPostQuantumCiphers = TestResult.TRUE;
            supportsEcmqv = TestResult.TRUE;
        }
        if (suite.name().contains("CECPQ1")) {
            supportsPostQuantumCiphers = TestResult.TRUE;
            supportsNewHope = TestResult.TRUE;
        }
        if (suite.name().contains("anon")) {
            supportsAnonCiphers = TestResult.TRUE;
        }
        if (suite.isEphemeral()) {
            supportsPfsCiphers = TestResult.TRUE;
        } else {
            supportsOnlyPfsCiphers = TestResult.FALSE;
        }
        if (suite.isExport()) {
            supportsExportCiphers = TestResult.TRUE;
        }
    }

    private void adjustBulk(CipherSuite suite) {
        BulkCipherAlgorithm bulkCipherAlgorithm = AlgorithmResolver.getBulkCipherAlgorithm(suite);
        switch (bulkCipherAlgorithm) {
            case AES:
                supportsAes = TestResult.TRUE;
                break;
            case CAMELLIA:
                supportsCamellia = TestResult.TRUE;
                break;
            case DES40:
                supportsDesCiphers = TestResult.TRUE;
                supportsExportCiphers = TestResult.TRUE;
                break;
            case DES:
                supportsDesCiphers = TestResult.TRUE;
                break;
            case ARIA:
                supportsAria = TestResult.TRUE;
                break;
            case DESede:
                supportsTripleDesCiphers = TestResult.TRUE;
                break;
            case FORTEZZA:
                supportsFortezza = TestResult.TRUE;
                break;
            case IDEA:
                supportsIdeaCiphers = TestResult.TRUE;
                break;
            case NULL:
                supportsNullCiphers = TestResult.TRUE;
                break;
            case RC2:
                supportsRc2Ciphers = TestResult.TRUE;
                break;
            case RC4:
                supportsRc4Ciphers = TestResult.TRUE;
                break;
            case SEED:
                supportsSeedCiphers = TestResult.TRUE;
                break;
            case CHACHA20_POLY1305:
                supportsChacha = TestResult.TRUE;
                break;
            default:
                ;
        }
    }

    private void adjustCertificate(CipherSuite suite) {
        if (suite.name().contains("ECDSA")) {
            supportsEcdsa = TestResult.TRUE;
        }
        if (suite.name().contains("DSS")) {
            supportsDss = TestResult.TRUE;
        }
        if (suite.name().contains("RSA")) {
            supportsRsaCert = TestResult.TRUE;
        }
    }

    private void writeToReport(SiteReport report) {
        report.putResult(AnalyzedProperty.SUPPORTS_NULL_CIPHERS, supportsNullCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_ANON, supportsAnonCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_EXPORT, supportsExportCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_DES, supportsDesCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_SEED, supportsSeedCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_IDEA, supportsIdeaCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_RC2, supportsRc2Ciphers);
        report.putResult(AnalyzedProperty.SUPPORTS_RC4, supportsRc4Ciphers);
        report.putResult(AnalyzedProperty.SUPPORTS_3DES, supportsTripleDesCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_POST_QUANTUM, supportsPostQuantumCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_AEAD, supportsAeadCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_PFS, supportsPfsCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_ONLY_PFS, supportsOnlyPfsCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_AES, supportsAes);
        report.putResult(AnalyzedProperty.SUPPORTS_CAMELLIA, supportsCamellia);
        report.putResult(AnalyzedProperty.SUPPORTS_ARIA, supportsAria);
        report.putResult(AnalyzedProperty.SUPPORTS_CHACHA, supportsChacha);
        report.putResult(AnalyzedProperty.SUPPORTS_RSA, supportsRsa);
        report.putResult(AnalyzedProperty.SUPPORTS_DH, supportsDh);
        report.putResult(AnalyzedProperty.SUPPORTS_STATIC_ECDH, supportsStaticEcdh);
        report.putResult(AnalyzedProperty.SUPPORTS_ECDSA, supportsEcdsa);
        report.putResult(AnalyzedProperty.SUPPORTS_RSA_CERT, supportsRsaCert);
        report.putResult(AnalyzedProperty.SUPPORTS_DSS, supportsDss);
        report.putResult(AnalyzedProperty.SUPPORTS_ECDH, supportsEcdh);
        report.putResult(AnalyzedProperty.SUPPORTS_GOST, supportsGost);
        report.putResult(AnalyzedProperty.SUPPORTS_SRP, supportsSrp);
        report.putResult(AnalyzedProperty.SUPPORTS_KERBEROS, supportsKerberos);
        report.putResult(AnalyzedProperty.SUPPORTS_PSK_PLAIN, supportsPskPlain);
        report.putResult(AnalyzedProperty.SUPPORTS_PSK_RSA, supportsPskRsa);
        report.putResult(AnalyzedProperty.SUPPORTS_PSK_DHE, supportsPskDhe);
        report.putResult(AnalyzedProperty.SUPPORTS_PSK_ECDHE, supportsPskEcdhe);
        report.putResult(AnalyzedProperty.SUPPORTS_FORTEZZA, supportsFortezza);
        report.putResult(AnalyzedProperty.SUPPORTS_NEWHOPE, supportsNewHope);
        report.putResult(AnalyzedProperty.SUPPORTS_ECMQV, supportsEcmqv);
        report.putResult(AnalyzedProperty.PREFERS_PFS, prefersPfsCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_STREAM_CIPHERS, supportsStreamCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS, supportsBlockCiphers);
        report.putResult(AnalyzedProperty.SUPPORTS_LEGACY_PRF, supportsLegacyPrf);
        report.putResult(AnalyzedProperty.SUPPORTS_SHA256_PRF, supportsSha256Prf);
        report.putResult(AnalyzedProperty.SUPPORTS_SHA384_PRF, supportsSha384Prf);
        report.setVersionSuitePairs(pairLists);
    }

}
