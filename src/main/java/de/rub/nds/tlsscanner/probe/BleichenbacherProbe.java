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
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BleichenbacherProbe extends TlsProbe {

    public BleichenbacherProbe(ScannerConfig config) {
        super(ProbeType.BLEICHENBACHER, config, 10);
    }

    @Override
    public ProbeResult executeTest() {
        BleichenbacherCommandConfig bleichenbacherConfig = new BleichenbacherCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) bleichenbacherConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        BleichenbacherAttacker attacker = new BleichenbacherAttacker(bleichenbacherConfig, bleichenbacherConfig.createConfig(),new ParallelExecutor(100, 3));
        Boolean vulnerable = attacker.isVulnerable();
        if (vulnerable == null && !getScannerConfig().isImplementation()) {
            vulnerable = false;
        }
        return new BleichenbacherResult(vulnerable);
    }

    @Override
    public boolean shouldBeExecuted(SiteReport report) {
        if (report.getSupportsRsa() == Boolean.TRUE) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public void adjustConfig(SiteReport report) {
    }

    @Override
    public ProbeResult getNotExecutedResult() {
        return new BleichenbacherResult(Boolean.FALSE);
    }
}
