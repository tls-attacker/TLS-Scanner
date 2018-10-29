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
import de.rub.nds.tlsattacker.attacks.padding.VectorResponse;
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
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleTestResult;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class PaddingOracleProbe extends TlsProbe {

    private Boolean supportsTls12;
    private Boolean supportsTls11;
    private Boolean supportsTls10;

    private List<VersionSuiteListPair> serverSupportedSuites;

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
        if (scannerConfig.getScanDetail() == ScannerDetail.ALL) {
            vectorTypeList.add(PaddingVectorGeneratorType.FINISHED);
            vectorTypeList.add(PaddingVectorGeneratorType.CLOSE_NOTIFY);
            vectorTypeList.add(PaddingVectorGeneratorType.FINISHED_RESUMPTION);
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
            VersionSuiteListPair suitePairList = null;
            for (VersionSuiteListPair versionSuiteList : serverSupportedSuites) {
                if (versionSuiteList.getVersion() == version) {
                    suitePairList = versionSuiteList;
                    break;
                }
            }
            if (suitePairList == null) {
                continue;
            }
            for (PaddingVectorGeneratorType vectorType : vectorTypeList) {
                Set<CipherSuite> set = new HashSet<>(suitePairList.getCiphersuiteList());
                filterSuite(set);
                for (CipherSuite suite : set) {
                    if (suite.isCBC() && CipherSuite.getImplemented().contains(suite)) {
                        cipherSuiteDelegate.setCipherSuites(suite);
                        versionDelegate.setProtocolVersion(version);
                        paddingOracleConfig.setRecordGeneratorType(recordGeneratorType);
                        paddingOracleConfig.setVectorGeneratorType(vectorType);
                        PaddingOracleAttacker attacker = new PaddingOracleAttacker(paddingOracleConfig, scannerConfig.createConfig(), getParallelExecutor());
                        boolean hasError = false;
                        try {
                            lastResult = attacker.isVulnerable();
                        } catch (Exception E) {
                            LOGGER.error("Encountered an exception while testing for PaddingOracles", E);
                            lastResult = null;
                            hasError = true;
                        }
                        if (attacker.isErrornousScans()) {
                            hasError = true;
                        }
                        for (VectorResponse vectorResponse : attacker.getVectorResponseList()) {
                            if (vectorResponse.isErrorDuringHandshake()) {
                                hasError = true;
                            }
                        }
                        testResultList.add(new PaddingOracleTestResult(lastResult, version, suite, paddingOracleConfig.getVectorGeneratorType(), paddingOracleConfig.getRecordGeneratorType(), attacker.getVectorResponseList(), attacker.getVectorResponseListTwo(), attacker.getVectorResponseListThree(), attacker.getEqualityError(attacker.getVectorResponseList()), attacker.isShakyScans(), hasError));
                    }
                }
            }
        }
        return new PaddingOracleResult(testResultList);
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        if (!(report.getSupportsTls10() == Boolean.TRUE) && !(report.getSupportsTls11() == Boolean.TRUE) && !(report.getSupportsTls12() == Boolean.TRUE)) {
            return false;
        }
        if (report.getCipherSuites() == null) {
            return false;
        }
        return Objects.equals(report.getSupportsBlockCiphers(), Boolean.TRUE) || report.getSupportsBlockCiphers() == null;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        supportsTls10 = report.getSupportsTls10();
        supportsTls11 = report.getSupportsTls11();
        supportsTls12 = report.getSupportsTls12();
        serverSupportedSuites = report.getVersionSuitePairs();
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new PaddingOracleResult(new LinkedList<PaddingOracleTestResult>());
    }

    private void filterSuite(Set<CipherSuite> set) {
        //This should remove ciphersuites accoding to the scanDetail
    }
}
