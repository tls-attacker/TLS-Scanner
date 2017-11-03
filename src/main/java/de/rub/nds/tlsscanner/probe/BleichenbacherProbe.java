/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.BleichenbacherAttacker;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.report.check.CheckType;
import de.rub.nds.tlsscanner.report.check.TLSCheck;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class BleichenbacherProbe extends TLSProbe {

    public BleichenbacherProbe(ScannerConfig config) {
        super(ProbeType.BLEICHENBACHER, config);
    }

    @Override
    public ProbeResult call() {
        LOGGER.debug("Starting BleichenbacherProbe");
        BleichenbacherCommandConfig bleichenbacherConfig = new BleichenbacherCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) bleichenbacherConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        BleichenbacherAttacker attacker = new BleichenbacherAttacker(bleichenbacherConfig);
        Boolean vulnerable = attacker.isVulnerable();
        TLSCheck check = new TLSCheck(vulnerable, CheckType.ATTACK_BLEICHENBACHER, 10);
        List<TLSCheck> checkList = new LinkedList<>();
        checkList.add(check);
        return new ProbeResult(getType(), new LinkedList<ResultValue>(), checkList);

    }

}
