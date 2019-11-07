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
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
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
            PaddingOracleCommandConfig paddingOracleConfig = new PaddingOracleCommandConfig(getScannerConfig().getGeneralDelegate());
            ClientDelegate delegate = (ClientDelegate) paddingOracleConfig.getDelegate(ClientDelegate.class);
            delegate.setHost(getScannerConfig().getClientDelegate().getHost());
            delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
            StarttlsDelegate starttlsDelegate = (StarttlsDelegate) paddingOracleConfig.getDelegate(StarttlsDelegate.class);
            starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
            List<PaddingOracleCipherSuiteFingerprint> testResultList = new LinkedList<>();
            PaddingRecordGeneratorType recordGeneratorType;
            if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
                recordGeneratorType = PaddingRecordGeneratorType.MEDIUM;
            } else if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.NORMAL)) {
                recordGeneratorType = PaddingRecordGeneratorType.SHORT;
            } else {
                recordGeneratorType = PaddingRecordGeneratorType.VERY_SHORT;
            }

            List<PaddingVectorGeneratorType> vectorTypeList = new LinkedList<>();
            vectorTypeList.add(PaddingVectorGeneratorType.CLASSIC_DYNAMIC);
            if (scannerConfig.getScanDetail() == ScannerDetail.ALL) {
                //vectorTypeList.add(PaddingVectorGeneratorType.FINISHED);
                //vectorTypeList.add(PaddingVectorGeneratorType.CLOSE_NOTIFY);
                //vectorTypeList.add(PaddingVectorGeneratorType.FINISHED_RESUMPTION);
            }
            for (PaddingVectorGeneratorType vectorGeneratorType : vectorTypeList) {
                for (VersionSuiteListPair pair : serverSupportedSuites) {
                    if (pair.getVersion() == ProtocolVersion.TLS10 || pair.getVersion() == ProtocolVersion.TLS11 || pair.getVersion() == ProtocolVersion.TLS12) {
                        for (CipherSuite suite : pair.getCiphersuiteList()) {
                            if (suite.isCBC() && CipherSuite.getImplemented().contains(suite)) {
                                testResultList.add(getPaddingOracleCipherSuiteFingerprintList(paddingOracleConfig, 3, true, vectorGeneratorType, recordGeneratorType, pair.getVersion(), suite));
                            }
                        }
                    }
                }
            }
            List<PaddingOracleCipherSuiteFingerprint> shakyScanEvaluation = new LinkedList<>();
            //Classic tests cannnot confirm a vulnerability - check for shaky scans

            return new PaddingOracleResponseMap(testResultList, shakyScanEvaluation, isVulnerable(testResultList));
        } catch (Exception e) {
            return new PaddingOracleResponseMap(new LinkedList<PaddingOracleCipherSuiteFingerprint>(), new LinkedList<PaddingOracleCipherSuiteFingerprint>(), TestResult.ERROR_DURING_TEST);
        }
    }

    private TestResult isVulnerable(List<PaddingOracleCipherSuiteFingerprint> list) {
        for (PaddingOracleCipherSuiteFingerprint fingerprint : list) {
            if (Objects.equals(fingerprint.getVulnerable(), Boolean.TRUE)) {
                return TestResult.TRUE;
            }
        }
        return TestResult.FALSE;
    }

    private PaddingOracleCipherSuiteFingerprint getPaddingOracleCipherSuiteFingerprintList(PaddingOracleCommandConfig paddingOracleConfig, int maxDepth, boolean earlyAbort, PaddingVectorGeneratorType vectorGeneratorType, PaddingRecordGeneratorType recordGeneratorType, ProtocolVersion version, CipherSuite suite) {
        paddingOracleConfig.setRecordGeneratorType(recordGeneratorType);
        paddingOracleConfig.setMapListDepth(maxDepth);
        paddingOracleConfig.setAbortRescansOnFailure(earlyAbort);
        paddingOracleConfig.setRescanNotVulnerable(false);
        paddingOracleConfig.setVectorGeneratorType(vectorGeneratorType);
        return evaluate(paddingOracleConfig, suite, version);
    }

    private PaddingOracleCipherSuiteFingerprint evaluate(PaddingOracleCommandConfig paddingOracleConfig, CipherSuite suite, ProtocolVersion version) {
        CiphersuiteDelegate cipherSuiteDelegate = (CiphersuiteDelegate) paddingOracleConfig.getDelegate(CiphersuiteDelegate.class);
        cipherSuiteDelegate.setCipherSuites(suite);
        ProtocolVersionDelegate versionDelegate = (ProtocolVersionDelegate) paddingOracleConfig.getDelegate(ProtocolVersionDelegate.class);
        versionDelegate.setProtocolVersion(version);
        PaddingOracleCipherSuiteFingerprint result = createTestResult(version, suite, paddingOracleConfig);
        return result;
    }

    private boolean isCandidateForShakyEvaluation(PaddingOracleCipherSuiteFingerprint fingerprint) {
        return fingerprint.isShakyScans() && !fingerprint.isHasScanningError();
    }

    private PaddingOracleCipherSuiteFingerprint createTestResult(ProtocolVersion version, CipherSuite suite, PaddingOracleCommandConfig paddingOracleConfig) {

        Boolean result;
        PaddingOracleAttacker attacker = new PaddingOracleAttacker(paddingOracleConfig, scannerConfig.createConfig(), getParallelExecutor());
        if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
            attacker.setAdditionalTimeout(1000);
            attacker.setIncreasingTimeout(true);
        } else {
            attacker.setAdditionalTimeout(50);
        }
        boolean hasError = false;
        try {
            result = attacker.isVulnerable();
        } catch (Exception E) {
            LOGGER.error("Encountered an exception while testing for PaddingOracles", E);
            result = null;
            hasError = true;
        }
        if (attacker.isErrornousScans()) {
            hasError = true;
        }
        EqualityError equalityError = attacker.getResultError();

        return new PaddingOracleCipherSuiteFingerprint(result, version, suite, paddingOracleConfig.getVectorGeneratorType(), paddingOracleConfig.getRecordGeneratorType(), attacker.getResponseMapList(), equalityError, attacker.isShakyScans(), hasError);
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
        return new PaddingOracleResponseMap(null, null, TestResult.COULD_NOT_TEST);
    }
}
