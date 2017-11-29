/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttacker;
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
 * @author Robert Merget - robert.merget@rub.de
 */
public class InvalidCurveProbe extends TLSProbe {

    public InvalidCurveProbe(ScannerConfig config) {
        super(ProbeType.INVALID_CURVE, config);
    }

    @Override
    public ProbeResult call() {
        LOGGER.debug("Starting InvalidCurveProbe");
        InvalidCurveAttackConfig invalidCurveAttackConfig = new InvalidCurveAttackConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) invalidCurveAttackConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        InvalidCurveAttacker attacker = new InvalidCurveAttacker(invalidCurveAttackConfig);
        Boolean vulnerable = attacker.isVulnerable();
        if (vulnerable == null) {
            vulnerable = false; //TODO
        }
        TLSCheck check = new TLSCheck(vulnerable, CheckType.ATTACK_INVALID_CURVE, 10);
        List<TLSCheck> checkList = new LinkedList<>();
        checkList.add(check);
        invalidCurveAttackConfig = new InvalidCurveAttackConfig(getScannerConfig().getGeneralDelegate());
        invalidCurveAttackConfig.setEphemeral(true);
        delegate = (ClientDelegate) invalidCurveAttackConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        attacker = new InvalidCurveAttacker(invalidCurveAttackConfig);
        vulnerable = attacker.isVulnerable();
        if (vulnerable == null) {
            vulnerable = false; //TODO
        }
        check = new TLSCheck(vulnerable, CheckType.ATTACK_INVALID_CURVE_EPHEMERAL, 10);
        checkList.add(check);
        
        return new ProbeResult(getType(), new LinkedList<ResultValue>(), checkList);
    }
}
