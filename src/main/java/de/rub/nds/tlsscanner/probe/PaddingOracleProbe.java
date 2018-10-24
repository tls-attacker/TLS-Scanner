/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.result.PaddingOracleResult;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsattacker.attacks.constants.PaddingVectorGeneratorType;
import de.rub.nds.tlsattacker.attacks.exception.PaddingOracleUnstableException;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.CiphersuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleTestResult;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class PaddingOracleProbe extends TlsProbe {

    private Boolean supportsTls12;
    private Boolean supportsTls11;
    private Boolean supportsTls10;

    public PaddingOracleProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.PADDING_ORACLE, config, 9);
    }

    @Override
    public ProbeResult executeTest() {
        PaddingOracleCommandConfig paddingOracleConfig = new PaddingOracleCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) paddingOracleConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());

        CiphersuiteDelegate cipherSuiteDelegate = (CiphersuiteDelegate) paddingOracleConfig.getDelegate(CiphersuiteDelegate.class);
        
        List<PaddingOracleTestResult> testResultList = new LinkedList<>();
        Boolean lastResult = null;
        PaddingRecordGeneratorType recordGeneratorType;
        if (scannerConfig.getScanDetail() == ScannerDetail.NORMAL) {
            recordGeneratorType = PaddingRecordGeneratorType.VERY_SHORT;
        } else {
            recordGeneratorType = PaddingRecordGeneratorType.SHORT;
        }

        List<PaddingVectorGeneratorType> vectorTypeList = new LinkedList<>();
        vectorTypeList.add(PaddingVectorGeneratorType.CLASSIC_DYNAMIC);
        if (scannerConfig.getScanDetail() == ScannerDetail.DETAILED || scannerConfig.getScanDetail() == ScannerDetail.ALL) {
            vectorTypeList.add(PaddingVectorGeneratorType.FINISHED);
            if (scannerConfig.getScanDetail() == ScannerDetail.ALL) {
                vectorTypeList.add(PaddingVectorGeneratorType.CLOSE_NOTIFY);
                vectorTypeList.add(PaddingVectorGeneratorType.FINISHED_RESUMPTION);
            }

        }
        List<ProtocolVersion> versionList = new LinkedList<>();
        if (supportsTls10 != null && supportsTls11 != null && supportsTls12 != null) {
            if (supportsTls10) {
                versionList.add(ProtocolVersion.TLS10);
            }
            if (supportsTls12) {
                versionList.add(ProtocolVersion.TLS12);
            } else if (supportsTls11) {
                versionList.add(ProtocolVersion.TLS11);
            }
        } else {
            versionList.add(ProtocolVersion.TLS12);
            if (scannerConfig.getScanDetail() == ScannerDetail.DETAILED || scannerConfig.getScanDetail() == ScannerDetail.ALL) {
                versionList.add(ProtocolVersion.TLS11);
                versionList.add(ProtocolVersion.TLS10);
            }
        }
        ProtocolVersionDelegate versionDelegate = (ProtocolVersionDelegate) paddingOracleConfig.getDelegate(ProtocolVersionDelegate.class);
        for (ProtocolVersion version : versionList) {
            List<CipherSuite> suiteList = new LinkedList<>();
            for (CipherSuite suite : CipherSuite.getImplemented()) {
                if (suite.isCBC()) {
                    suiteList.add(suite);
                }
            }
            for (PaddingVectorGeneratorType vectorType : vectorTypeList) {
                CipherSuite testedSuite = null;
                ProtocolVersion testedVersion = null;
                do {
                    cipherSuiteDelegate.setCipherSuites(suiteList);
                    versionDelegate.setProtocolVersion(version);
                    paddingOracleConfig.setRecordGeneratorType(recordGeneratorType);
                    paddingOracleConfig.setVectorGeneratorType(vectorType);
                    PaddingOracleAttacker attacker = new PaddingOracleAttacker(paddingOracleConfig, paddingOracleConfig.createConfig(), getParallelExecutor());
                    boolean hasError = false;
                    try {
                        lastResult = attacker.isVulnerable();
                    } catch (PaddingOracleUnstableException E) {
                        LOGGER.warn("PaddingOracle Unstable - you should probably test this manually", E);
                        lastResult = null;
                        hasError = true;
                    }
                    testedSuite = attacker.getTestedSuite();
                    testedVersion = attacker.getTestedVersion();
                    if (!suiteList.contains(testedSuite)) {
                        LOGGER.warn("Server does not respect client ciphersuite offer");
                        break;
                    }
                    if (testedSuite != null && testedVersion != null) {
                        if (!containsTupleAlready(testResultList, attacker.getTestedVersion(), attacker.getTestedSuite(), vectorType)) {
                            testResultList.add(new PaddingOracleTestResult(lastResult, testedVersion, testedSuite, paddingOracleConfig.getVectorGeneratorType(), paddingOracleConfig.getRecordGeneratorType(), attacker.getResponseMap(), attacker.getEqualityError(attacker.getResponseMap()), attacker.isShakyScans(), hasError));
                        }
                        if (scannerConfig.getScanDetail() == ScannerDetail.NORMAL) {
                            String suffix = attacker.getTestedSuite().name().split("WITH_")[1];
                            List<CipherSuite> tempList = new LinkedList<>();
                            for (CipherSuite suite : suiteList) {
                                if (!suite.name().endsWith(suffix)) {
                                    tempList.add(suite);
                                }
                            }
                            suiteList = tempList;
                        } else {
                            suiteList.remove(testedSuite);
                        }
                    }
                } while (testedVersion != null && testedSuite != null);
            }

        }
        System.out.println("testresults:" + testResultList.size());
        return new PaddingOracleResult(testResultList);
    }

    private boolean containsTupleAlready(List<PaddingOracleTestResult> testResultList, ProtocolVersion version, CipherSuite suite, PaddingVectorGeneratorType vectorGeneratorType) {
        for (PaddingOracleTestResult result : testResultList) {
            if (result.getSuite() == suite && result.getVersion() == version && result.getVectorGeneratorType() == vectorGeneratorType) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        if (!report.getSupportsTls10() && !report.getSupportsTls11() && !report.getSupportsTls12()) {
            return false;
        }
        return Objects.equals(report.getSupportsBlockCiphers(), Boolean.TRUE) || report.getSupportsBlockCiphers() == null;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportsTls10 = report.getSupportsTls10();
        supportsTls11 = report.getSupportsTls11();
        supportsTls12 = report.getSupportsTls12();
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new PaddingOracleResult(new LinkedList<PaddingOracleTestResult>());
    }
}
