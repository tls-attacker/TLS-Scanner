/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.HeartbleedCommandConfig;
import de.rub.nds.tlsattacker.attacks.config.PaddingOracleCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.HeartbleedAttacker;
import de.rub.nds.tlsattacker.attacks.impl.PaddingOracleAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.report.check.CheckType;
import de.rub.nds.tlsscanner.report.check.TlsCheck;
import de.rub.nds.tlsscanner.report.result.HeartbleedResult;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class HeartbleedProbe extends TlsProbe {

    public HeartbleedProbe(ScannerConfig config) {
        super(ProbeType.HEARTBLEED, config, 9);
    }

    @Override
    public ProbeResult call() {
        LOGGER.debug("Starting HeartbleedProbe");
        HeartbleedCommandConfig heartbleedConfig = new HeartbleedCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) heartbleedConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        HeartbleedAttacker attacker = new HeartbleedAttacker(heartbleedConfig);
        Boolean vulnerable = attacker.isVulnerable();
        return new HeartbleedResult(vulnerable);
    }

}
