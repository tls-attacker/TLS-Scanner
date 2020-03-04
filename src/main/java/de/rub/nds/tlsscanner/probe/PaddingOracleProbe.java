/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.result.PaddingOracleResponseMap;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttacker;
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleCipherSuiteFingerprint;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class PaddingOracleProbe extends TlsProbe {

    private List<VersionSuiteListPair> serverSupportedSuites;

    public PaddingOracleProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.PADDING_ORACLE, config, 9);
    }

    @Override
    public ProbeResult executeTest() {
        try {
            List<PaddingVectorGeneratorType> vectorTypeList = createVectorTypeList();
            List<PaddingOracleCipherSuiteFingerprint> testResultList = new LinkedList<>();
            for (PaddingVectorGeneratorType vectorGeneratorType : vectorTypeList) {
                for (VersionSuiteListPair pair : serverSupportedSuites) {
                    if (pair.getVersion() == ProtocolVersion.TLS10 || pair.getVersion() == ProtocolVersion.TLS11 || pair.getVersion() == ProtocolVersion.TLS12) {
                        for (CipherSuite suite : pair.getCiphersuiteList()) {
                            if (suite.isCBC() && CipherSuite.getImplemented().contains(suite)) {
                                PaddingOracleCommandConfig paddingOracleConfig = createPaddingOracleCommandConfig(pair.getVersion(), suite);
                                paddingOracleConfig.setVectorGeneratorType(vectorGeneratorType);
                                testResultList.add(getPaddingOracleCipherSuiteFingerprint(paddingOracleConfig));
                            }
                        }
                    }
                }
            }
            //If we found some difference in the server behavior we need to 
            if (isPotentiallyVulnerable(testResultList) || scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL)) {
                LOGGER.debug("We found non-determinism during the padding oracle scan");
                LOGGER.debug("Starting non-determinism evaluation");
                for (PaddingOracleCipherSuiteFingerprint fingerprint : testResultList) {
                    if (isPotentiallyVulnerable(fingerprint) || scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
                        LOGGER.debug("Found a candidate for the non-determinism eval:" + fingerprint.getSuite() + " - " + fingerprint.getVersion());
                        extendFingerPrint(fingerprint, 7);
                    }
                }
                LOGGER.debug("Finished non-determinism evaluation");
            }
            return new PaddingOracleResponseMap(testResultList);
        } catch (Exception e) {
            LOGGER.error(e);
            return new PaddingOracleResponseMap(new LinkedList<>());
        }
    }

    private List<PaddingVectorGeneratorType> createVectorTypeList() {
        List<PaddingVectorGeneratorType> vectorTypeList = new LinkedList<>();
        vectorTypeList.add(PaddingVectorGeneratorType.CLASSIC_DYNAMIC);
        if (scannerConfig.getScanDetail() == ScannerDetail.ALL) {
            vectorTypeList.add(PaddingVectorGeneratorType.FINISHED);
            vectorTypeList.add(PaddingVectorGeneratorType.CLOSE_NOTIFY);
            vectorTypeList.add(PaddingVectorGeneratorType.FINISHED_RESUMPTION);
        }
        return vectorTypeList;
    }

    private PaddingOracleCommandConfig createPaddingOracleCommandConfig(ProtocolVersion version, CipherSuite cipherSuite) {
        PaddingOracleCommandConfig paddingOracleConfig = new PaddingOracleCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) paddingOracleConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
        StarttlsDelegate starttlsDelegate = (StarttlsDelegate) paddingOracleConfig.getDelegate(StarttlsDelegate.class);
        starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
        PaddingRecordGeneratorType recordGeneratorType;
        paddingOracleConfig.setNumberOfIterations(2);
        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL)) {
            recordGeneratorType = PaddingRecordGeneratorType.SHORT;
            paddingOracleConfig.setNumberOfIterations(3);
        } else {
            recordGeneratorType = PaddingRecordGeneratorType.VERY_SHORT;
            paddingOracleConfig.setNumberOfIterations(1);
        }
        paddingOracleConfig.setRecordGeneratorType(recordGeneratorType);
        paddingOracleConfig.getCiphersuiteDelegate().setCipherSuites(cipherSuite);
        paddingOracleConfig.getProtocolVersionDelegate().setProtocolVersion(version);
        return paddingOracleConfig;
    }

    private PaddingOracleCipherSuiteFingerprint getPaddingOracleCipherSuiteFingerprint(PaddingOracleCommandConfig paddingOracleConfig) {

        PaddingOracleAttacker attacker = new PaddingOracleAttacker(paddingOracleConfig, scannerConfig.createConfig(), getParallelExecutor());
        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
            attacker.setAdditionalTimeout(1000);
            attacker.setIncreasingTimeout(true);
        } else {
            attacker.setAdditionalTimeout(50);
        }
        try {
            attacker.isVulnerable();
        } catch (Exception E) {
            LOGGER.error("Encountered an exception while testing for PaddingOracles", E);
        }
        return new PaddingOracleCipherSuiteFingerprint(paddingOracleConfig.getProtocolVersionDelegate().getProtocolVersion(), paddingOracleConfig.getCiphersuiteDelegate().getCipherSuites().get(0), paddingOracleConfig.getVectorGeneratorType(), paddingOracleConfig.getRecordGeneratorType(), attacker.getResponseMapList());
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        if (!(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_0), TestResult.TRUE)) && !(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_1), TestResult.TRUE)) && !(Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_TLS_1_2), TestResult.TRUE))) {
            return false;
        }
        if (report.getCipherSuites() == null) {
            return false;
        }
        return Objects.equals(report.getResult(AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS), TestResult.TRUE);
    }

    @Override
    public void adjustConfig(SiteReport report) {
        serverSupportedSuites = report.getVersionSuitePairs();
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new PaddingOracleResponseMap(null);
    }

    private void extendFingerPrint(PaddingOracleCipherSuiteFingerprint fingerprint, int numberOfAdditionalIterations) {
        PaddingOracleCommandConfig paddingOracleCommandConfig = createPaddingOracleCommandConfig(fingerprint.getVersion(), fingerprint.getSuite());
        paddingOracleCommandConfig.setRecordGeneratorType(fingerprint.getRecordGeneratorType());
        paddingOracleCommandConfig.setVectorGeneratorType(fingerprint.getVectorGeneratorType());
        paddingOracleCommandConfig.setNumberOfIterations(numberOfAdditionalIterations);
        PaddingOracleCipherSuiteFingerprint tempFingerprint = getPaddingOracleCipherSuiteFingerprint(paddingOracleCommandConfig);
        fingerprint.appendToResponseMap(tempFingerprint.getResponseMap());
    }

    private boolean isPotentiallyVulnerable(List<PaddingOracleCipherSuiteFingerprint> testResultList) {
        for (PaddingOracleCipherSuiteFingerprint fingerprint : testResultList) {
            if (isPotentiallyVulnerable(fingerprint)) {
                return true;
            }
        }
        return false;
    }

    private boolean isPotentiallyVulnerable(PaddingOracleCipherSuiteFingerprint fingerprint) {
        for (VectorResponse responseA : fingerprint.getResponseMap()) {
            for (VectorResponse responseB : fingerprint.getResponseMap()) {
                if (!responseA.getFingerprint().equals(responseB.getFingerprint())) {
                    return true;
                }
            }
        }
        return false;
    }
}
