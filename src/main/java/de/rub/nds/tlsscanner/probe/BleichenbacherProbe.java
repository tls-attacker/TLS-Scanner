/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsscanner.report.result.BleichenbacherResult;
import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
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
    public ProbeResult call() {
        LOGGER.debug("Starting BleichenbacherProbe");
        BleichenbacherCommandConfig bleichenbacherConfig = new BleichenbacherCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) bleichenbacherConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        BleichenbacherAttacker attacker = new BleichenbacherAttacker(bleichenbacherConfig);
        Boolean vulnerable = attacker.isVulnerable();
        return new BleichenbacherResult(vulnerable);

    }

}
