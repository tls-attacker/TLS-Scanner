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
import de.rub.nds.tlsattacker.attacks.config.PoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.PoodleAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.PoodleResult;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class PoodleProbe extends TlsProbe {

    public PoodleProbe(ScannerConfig config) {
        super(ProbeType.POODLE, config, 0);
    }

    @Override
    public ProbeResult call() {
        LOGGER.debug("Starting Poodle Probe");
        PoodleCommandConfig poodleCommandConfig = new PoodleCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) poodleCommandConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        PoodleAttacker attacker = new PoodleAttacker(poodleCommandConfig);
        Boolean vulnerable = attacker.isVulnerable();
        return new PoodleResult(vulnerable);
    }

}
