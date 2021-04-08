/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttacker;
import de.rub.nds.tlsattacker.attacks.pkcs1.BleichenbacherWorkflowType;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.core.config.delegate.CipherSuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import de.rub.nds.tlsscanner.serverscanner.report.result.BleichenbacherResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.serverscanner.report.result.bleichenbacher.BleichenbacherTestResult;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class BleichenbacherProbe extends TlsProbe {

    private List<CipherSuite> suiteList;

    public BleichenbacherProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.BLEICHENBACHER, config);
        suiteList = new LinkedList<>();
    }

    @Override
    public ProbeResult executeTest() {
        try {
            BleichenbacherCommandConfig bleichenbacherConfig =
                new BleichenbacherCommandConfig(getScannerConfig().getGeneralDelegate());
            ClientDelegate delegate = (ClientDelegate) bleichenbacherConfig.getDelegate(ClientDelegate.class);
            StarttlsDelegate starttlsDelegate =
                (StarttlsDelegate) bleichenbacherConfig.getDelegate(StarttlsDelegate.class);
            starttlsDelegate.setStarttlsType(scannerConfig.getStarttlsDelegate().getStarttlsType());
            delegate.setHost(getScannerConfig().getClientDelegate().getHost());
            delegate.setSniHostname(getScannerConfig().getClientDelegate().getSniHostname());
            ((CipherSuiteDelegate) (bleichenbacherConfig.getDelegate(CipherSuiteDelegate.class)))
                .setCipherSuites(suiteList);
            if (scannerConfig.getScanDetail().isGreaterEqualTo(ScannerDetail.DETAILED)) {
                bleichenbacherConfig.setType(BleichenbacherCommandConfig.Type.FULL);
            } else {
                bleichenbacherConfig.setType(BleichenbacherCommandConfig.Type.FAST);
            }
            List<BleichenbacherTestResult> resultList = new LinkedList<>();
            boolean vulnerable = false;
            for (BleichenbacherWorkflowType bbWorkflowType : BleichenbacherWorkflowType.values()) {
                bleichenbacherConfig.setWorkflowType(bbWorkflowType);
                LOGGER.debug("Testing: " + bbWorkflowType);
                BleichenbacherAttacker attacker = new BleichenbacherAttacker(bleichenbacherConfig,
                    scannerConfig.createConfig(), getParallelExecutor());
                EqualityError errorType = attacker.getEqualityError();
                vulnerable |= (errorType != EqualityError.NONE);
                resultList.add(new BleichenbacherTestResult(errorType != EqualityError.NONE,
                    bleichenbacherConfig.getType(), bbWorkflowType, attacker.getFingerprintPairList(), errorType));
            }
            return new BleichenbacherResult(vulnerable == true ? TestResult.TRUE : TestResult.FALSE, resultList);
        } catch (Exception e) {
            LOGGER.error("Could not scan for " + getProbeName(), e);
            return new BleichenbacherResult(TestResult.ERROR_DURING_TEST, new LinkedList<BleichenbacherTestResult>());
        }
    }

    @Override
    public boolean canBeExecuted(SiteReport report) {
        return report.getResult(AnalyzedProperty.SUPPORTS_RSA) == TestResult.TRUE;
    }

    @Override
    public void adjustConfig(SiteReport report) {
        if (report.getCipherSuites() != null) {
            for (CipherSuite suite : report.getCipherSuites()) {
                if (AlgorithmResolver.getKeyExchangeAlgorithm(suite) == KeyExchangeAlgorithm.RSA) {
                    suiteList.add(suite);
                }
            }
        } else {
            for (CipherSuite suite : CipherSuite.values()) {
                if (AlgorithmResolver.getKeyExchangeAlgorithm(suite) == KeyExchangeAlgorithm.RSA) {
                    suiteList.add(suite);
                }
            }
        }
    }

    @Override
    public ProbeResult getCouldNotExecuteResult() {
        return new BleichenbacherResult(TestResult.COULD_NOT_TEST, null);
    }
}
