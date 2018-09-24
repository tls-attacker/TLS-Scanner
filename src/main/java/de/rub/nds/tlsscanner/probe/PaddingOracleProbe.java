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
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleTestResult;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class PaddingOracleProbe extends TlsProbe {

    public PaddingOracleProbe(ScannerConfig config) {
        super(ProbeType.PADDING_ORACLE, config, 9, 224);
    }

    @Override
    public ProbeResult executeTest() {
        PaddingOracleCommandConfig paddingOracleConfig = new PaddingOracleCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) paddingOracleConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());

        CiphersuiteDelegate cipherSuiteDelegate = (CiphersuiteDelegate) paddingOracleConfig.getDelegate(CiphersuiteDelegate.class);
        List<CipherSuite> suiteList = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isCBC()) {
                suiteList.add(suite);
            }
        }
        cipherSuiteDelegate.setCipherSuites(suiteList);
        List<PaddingOracleTestResult> testResultList = new LinkedList<>();
        Boolean lastResult = null;
        PaddingRecordGeneratorType recordGeneratorType;
        if (scannerConfig.getScanDetail() != ScannerDetail.ALL) {
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
        versionList.add(ProtocolVersion.TLS12);
        if (scannerConfig.getScanDetail() == ScannerDetail.DETAILED || scannerConfig.getScanDetail() == ScannerDetail.ALL) {
            versionList.add(ProtocolVersion.TLS11);
            versionList.add(ProtocolVersion.TLS10);
        }
        ProtocolVersionDelegate versionDelegate = (ProtocolVersionDelegate) paddingOracleConfig.getDelegate(ProtocolVersionDelegate.class);

        for (ProtocolVersion version : versionList) {
            for (PaddingVectorGeneratorType vectorType : vectorTypeList) {
                do {
                    cipherSuiteDelegate.setCipherSuites(suiteList);
                    versionDelegate.setProtocolVersion(version);
                    paddingOracleConfig.setRecordGeneratorType(recordGeneratorType);
                    paddingOracleConfig.setVectorGeneratorType(vectorType);
                    PaddingOracleAttacker attacker = new PaddingOracleAttacker(paddingOracleConfig, paddingOracleConfig.createConfig());
                    try {
                        lastResult = attacker.isVulnerable();
                    } catch (PaddingOracleUnstableException E) {
                        LOGGER.warn("PaddingOracle Unstable - you should probably test this manually");
                        lastResult = null;
                    }
                    if ((lastResult == Boolean.TRUE || lastResult == Boolean.FALSE) && attacker.getTestedSuite() != null && attacker.getTestedVersion() != null) {
                        if (!containsTupleAlready(testResultList, attacker.getTestedVersion(), attacker.getTestedSuite(), vectorType)) {
                            testResultList.add(new PaddingOracleTestResult(lastResult, attacker.getTestedVersion(), attacker.getTestedSuite(), paddingOracleConfig.getVectorGeneratorType(), paddingOracleConfig.getRecordGeneratorType(), attacker.getResponseMap(), attacker.getEqualityError(attacker.getResponseMap())));
                        }
                        String suffix = attacker.getTestedSuite().name().split("WITH_")[1];
                        List<CipherSuite> tempList = new LinkedList<>();
                        for (CipherSuite suite : suiteList) {
                            if (!suite.name().endsWith(suffix)) {
                                tempList.add(suite);
                            }
                        }
                        suiteList = tempList;
                    } else {
                        lastResult = null;
                    }

                } while (lastResult != null);
            }
        }
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
        return report.getSupportsBlockCiphers() == Boolean.TRUE || report.getSupportsBlockCiphers() == null;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new PaddingOracleResult(new LinkedList<PaddingOracleTestResult>());
    }
}
