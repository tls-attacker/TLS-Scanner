/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.report.result.BleichenbacherResult;
import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttacker;
import de.rub.nds.tlsattacker.attacks.pkcs1.BleichenbacherWorkflowType;
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1Vector;
import de.rub.nds.tlsattacker.attacks.pkcs1.Pkcs1VectorGenerator;
import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.bleichenbacher.BleichenbacherTestResult;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BleichenbacherProbe extends TlsProbe {

    public BleichenbacherProbe(ScannerConfig config, ParallelExecutor parallelExecutor) {
        super(parallelExecutor, ProbeType.BLEICHENBACHER, config, 10);
    }

    @Override
    public ProbeResult executeTest() {
        BleichenbacherCommandConfig bleichenbacherConfig = new BleichenbacherCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) bleichenbacherConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());

        RSAPublicKey publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(bleichenbacherConfig.createConfig());
        if (publicKey == null) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return getNotExecutedResult();
        }
        LOGGER.info("Fetched the following server public key: " + publicKey);
        List<Pkcs1Vector> pkcs1Vectors;
        if (scannerConfig.getScanDetail() == ScannerDetail.NORMAL) {
            pkcs1Vectors = Pkcs1VectorGenerator.generatePkcs1Vectors(publicKey, BleichenbacherCommandConfig.Type.FAST,
                    bleichenbacherConfig.createConfig().getDefaultHighestClientProtocolVersion());
        } else {
            pkcs1Vectors = Pkcs1VectorGenerator.generatePkcs1Vectors(publicKey, BleichenbacherCommandConfig.Type.FULL,
                    bleichenbacherConfig.createConfig().getDefaultHighestClientProtocolVersion());
        }
        List<BleichenbacherTestResult> resultList = new LinkedList<>();
        boolean vulnerable = false;
        for (BleichenbacherWorkflowType bbWorkflowType : BleichenbacherWorkflowType.values()) {
            LOGGER.debug("Testing: " + bbWorkflowType);
            BleichenbacherAttacker attacker = new BleichenbacherAttacker(bleichenbacherConfig, scannerConfig.createConfig(), getParallelExecutor());
            EqualityError errorType = attacker.isVulnerable(bbWorkflowType, pkcs1Vectors);
            vulnerable |= (errorType != EqualityError.NONE);
            resultList.add(new BleichenbacherTestResult(errorType != EqualityError.NONE, bleichenbacherConfig.getType(), bbWorkflowType, attacker.getFingerprintPairList(), errorType));
        }
        return new BleichenbacherResult(vulnerable, resultList);
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        return report.getSupportsRsa() == Boolean.TRUE;
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new BleichenbacherResult(Boolean.FALSE, new LinkedList<BleichenbacherTestResult>());
    }
}
