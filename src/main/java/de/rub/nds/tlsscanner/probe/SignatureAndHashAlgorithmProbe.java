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
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.result.ProbeResult;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SignatureAndHashAlgorithmProbe extends TlsProbe {

    public SignatureAndHashAlgorithmProbe(ScannerConfig config) {
        super(ProbeType.SIGNATURE_AND_HASH, config, 4);
    }

    @Override
    public ProbeResult call() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
