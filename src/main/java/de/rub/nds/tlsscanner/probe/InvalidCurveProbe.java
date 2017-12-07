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
import de.rub.nds.tlsattacker.attacks.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsattacker.attacks.impl.InvalidCurveAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.result.InvalidCurveResult;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class InvalidCurveProbe extends TlsProbe {

    public InvalidCurveProbe(ScannerConfig config) {
        super(ProbeType.INVALID_CURVE, config, 10);
    }

    @Override
    public ProbeResult call() {
        LOGGER.debug("Starting InvalidCurveProbe");
        InvalidCurveAttackConfig invalidCurveAttackConfig = new InvalidCurveAttackConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) invalidCurveAttackConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        InvalidCurveAttacker attacker = new InvalidCurveAttacker(invalidCurveAttackConfig);
        Boolean vulnerableClassic = attacker.isVulnerable();
        invalidCurveAttackConfig = new InvalidCurveAttackConfig(getScannerConfig().getGeneralDelegate());
        invalidCurveAttackConfig.setEphemeral(true);
        delegate = (ClientDelegate) invalidCurveAttackConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        attacker = new InvalidCurveAttacker(invalidCurveAttackConfig);
        Boolean vulnerableEphemeral = attacker.isVulnerable();
        if (!getScannerConfig().isImplementation()) {
            if (vulnerableClassic == null) {
                vulnerableClassic = false;
            }
            if (vulnerableEphemeral == null) {
                vulnerableClassic = false;
            }
        }
        return new InvalidCurveResult(vulnerableClassic, vulnerableEphemeral);
    }
}
