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
import de.rub.nds.tlsattacker.attacks.config.TLSPoodleCommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.TLSPoodleAttacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.result.ProbeResult;
import de.rub.nds.tlsscanner.report.result.TlsPoodleResult;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsPoodleProbe extends TlsProbe {

    public TlsPoodleProbe(ScannerConfig config) {
        super(ProbeType.TLS_POODLE, config, 8);
    }

    @Override
    public ProbeResult call() {
        LOGGER.debug("Starting TLS-Poodle Probe");
        TLSPoodleCommandConfig poodleCommandConfig = new TLSPoodleCommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) poodleCommandConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        TLSPoodleAttacker attacker = new TLSPoodleAttacker(poodleCommandConfig);
        Boolean vulnerable = attacker.isVulnerable();
        return new TlsPoodleResult(vulnerable);
    }

}
