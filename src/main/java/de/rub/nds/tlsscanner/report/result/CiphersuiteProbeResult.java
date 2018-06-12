/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.BulkCipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CiphersuiteProbeResult extends ProbeResult {

    private List<VersionSuiteListPair> pairLists;

    private Boolean supportsNullCiphers = false;
    private Boolean supportsAnonCiphers = false;
    private Boolean supportsExportCiphers = false;
    private Boolean supportsDesCiphers = false;
    private Boolean supportsSeedCiphers = false;
    private Boolean supportsIdeaCiphers = false;
    private Boolean supportsRc2Ciphers = false;
    private Boolean supportsRc4Ciphers = false;
    private Boolean supportsTrippleDesCiphers = false;
    private Boolean supportsPostQuantumCiphers = false;
    private Boolean supportsAeadCiphers = false;
    private Boolean supportsPfsCiphers = false;
    private Boolean supportsOnlyPfsCiphers = false;
    private Boolean supportsAes = false;
    private Boolean supportsCamellia = false;
    private Boolean supportsAria = false;
    private Boolean supportsChacha = false;
    private Boolean supportsRsa = false;
    private Boolean supportsDh = false;
    private Boolean supportsEcdh = false;
    private Boolean supportsStaticEcdh = false;
    private Boolean supportsGost = false;
    private Boolean supportsSrp = null;
    private Boolean supportsKerberos = false;
    private Boolean supportsPskPlain = false;
    private Boolean supportsPskRsa = false;
    private Boolean supportsPskDhe = false;
    private Boolean supportsPskEcdhe = false;
    private Boolean supportsFortezza = false;
    private Boolean supportsNewHope = false;
    private Boolean supportsEcmqv = false;
    private Boolean prefersPfsCiphers = false;
    private Boolean supportsStreamCiphers = false;
    private Boolean supportsBlockCiphers = false;

    public CiphersuiteProbeResult(List<VersionSuiteListPair> pairLists) {
        super(ProbeType.CIPHERSUITE);
        this.pairLists = pairLists;
    }

    @Override
    public void merge(SiteReport report) {
        Set<CipherSuite> allSupported = new HashSet<>();
        supportsOnlyPfsCiphers = true;
        prefersPfsCiphers = true;
        for (VersionSuiteListPair pair : pairLists) {
            if (pair.getCiphersuiteList().size() > 0 && !pair.getCiphersuiteList().get(0).isEphemeral()) {
                prefersPfsCiphers = false;
            }
            allSupported.addAll(pair.getCiphersuiteList());
        }
        for (CipherSuite suite : allSupported) {
            adjustBulk(suite);
            adjustKeyExchange(suite);
            adjustCipherType(suite);
        }
        report.setCipherSuites(allSupported);

        writeToReport(report);
    }

    private void adjustCipherType(CipherSuite suite) {
        CipherType cipherType = AlgorithmResolver.getCipherType(suite);
        switch (cipherType) {
            case AEAD:
                supportsAeadCiphers = true;
                break;
            case BLOCK:
                supportsBlockCiphers = true;
                break;
            case STREAM:
                supportsStreamCiphers = true;
                break;
        }
    }

    private void adjustKeyExchange(CipherSuite suite) {
        if (suite.name().contains("SRP")) {
            supportsSrp = true;
        }
        if (suite.name().contains("_DH")) {
            supportsDh = true;
        }
        if (suite.name().contains("TLS_RSA")) {
            supportsRsa = true;
        }
        if (suite.name().contains("ECDH_")) {
            supportsStaticEcdh = true;
        }
        if (suite.name().contains("ECDH")) {
            supportsEcdh = true;
        }
        if (suite.name().contains("NULL")) {
            supportsNullCiphers = true;
        }
        if (suite.name().contains("GOST")) {
            supportsGost = true;
        }
        if (suite.name().contains("KRB5")) {
            supportsKerberos = true;
        }
        if (suite.name().contains("TLS_PSK_WITH")) {
            supportsPskPlain = true;
        }
        if (suite.name().contains("_DHE_PSK")) {
            supportsPskDhe = true;
        }
        if (suite.name().contains("ECDHE_PSK")) {
            supportsPskEcdhe = true;
        }
        if (suite.name().contains("RSA_PSK")) {
            supportsPskRsa = true;
        }
        if (suite.name().contains("FORTEZZA")) {
            supportsFortezza = true;
        }
        if (suite.name().contains("ECMQV")) {
            supportsPostQuantumCiphers = true;
            supportsEcmqv = true;
        }
        if (suite.name().contains("CECPQ1")) {
            supportsPostQuantumCiphers = true;
            supportsNewHope = true;
        }
        if (suite.name().contains("anon")) {
            supportsAnonCiphers = true;
        }
        if (suite.isEphemeral()) {
            supportsPfsCiphers = true;
        } else {
            supportsOnlyPfsCiphers = false;
        }
        if (suite.isExport()) {
            supportsExportCiphers = true;
        }
    }

    private void adjustBulk(CipherSuite suite) {
        BulkCipherAlgorithm bulkCipherAlgorithm = AlgorithmResolver.getBulkCipherAlgorithm(suite);
        switch (bulkCipherAlgorithm) {
            case AES:
                supportsAes = true;
                break;
            case CAMELLIA:
                supportsCamellia = true;
                break;
            case DES40:
                supportsDesCiphers = true;
                supportsExportCiphers = true;
                break;
            case DES:
                supportsDesCiphers = true;
                break;
            case ARIA:
                supportsAria = true;
                break;
            case DESede:
                supportsTrippleDesCiphers = true;
                break;
            case FORTEZZA:
                supportsFortezza = true;
                break;
            case IDEA:
                supportsIdeaCiphers = true;
                break;
            case NULL:
                supportsNullCiphers = true;
                break;
            case RC2:
                supportsRc2Ciphers = true;
                break;
            case RC4:
                supportsRc4Ciphers = true;
                break;
            case SEED:
                supportsSeedCiphers = true;
                break;
            case CHACHA20_POLY1305:
                supportsChacha = true;
                break;
        }
    }

    private void writeToReport(SiteReport report) {
        report.setSupportsNullCiphers(supportsNullCiphers);
        report.setSupportsAnonCiphers(supportsAnonCiphers);
        report.setSupportsExportCiphers(supportsExportCiphers);
        report.setSupportsDesCiphers(supportsDesCiphers);
        report.setSupportsSeedCiphers(supportsSeedCiphers);
        report.setSupportsIdeaCiphers(supportsIdeaCiphers);
        report.setSupportsRc2Ciphers(supportsRc2Ciphers);
        report.setSupportsRc4Ciphers(supportsRc4Ciphers);
        report.setSupportsTrippleDesCiphers(supportsTrippleDesCiphers);
        report.setSupportsPostQuantumCiphers(supportsPostQuantumCiphers);
        report.setSupportsAeadCiphers(supportsAeadCiphers);
        report.setSupportsPfsCiphers(supportsPfsCiphers);
        report.setSupportsOnlyPfsCiphers(supportsOnlyPfsCiphers);
        report.setSupportsAes(supportsAes);
        report.setSupportsCamellia(supportsCamellia);
        report.setSupportsAria(supportsAria);
        report.setSupportsChacha(supportsChacha);
        report.setSupportsRsa(supportsRsa);
        report.setSupportsDh(supportsDh);
        report.setSupportsStaticEcdh(supportsStaticEcdh);
        report.setSupportsEcdh(supportsEcdh);
        report.setSupportsGost(supportsGost);
        report.setSupportsSrp(supportsSrp);
        report.setSupportsKerberos(supportsKerberos);
        report.setSupportsPskPlain(supportsPskPlain);
        report.setSupportsPskRsa(supportsPskRsa);
        report.setSupportsPskDhe(supportsPskDhe);
        report.setSupportsPskEcdhe(supportsPskEcdhe);
        report.setSupportsFortezza(supportsFortezza);
        report.setSupportsNewHope(supportsNewHope);
        report.setSupportsEcmqv(supportsEcmqv);
        report.setPrefersPfsCiphers(prefersPfsCiphers);
        report.setSupportsStreamCiphers(supportsStreamCiphers);
        report.setSupportsBlockCiphers(supportsBlockCiphers);
        report.setVersionSuitePairs(pairLists);
    }

}
