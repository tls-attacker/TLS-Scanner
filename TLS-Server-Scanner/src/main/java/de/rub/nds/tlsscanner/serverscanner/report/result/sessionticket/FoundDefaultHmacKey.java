/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result.sessionticket;

import java.io.Serializable;

import de.rub.nds.tlsattacker.core.constants.MacAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketMacFormat;

public class FoundDefaultHmacKey implements Serializable {
    public final MacAlgorithm algorithm;
    public final SessionTicketMacFormat format;
    public final byte[] key;

    public FoundDefaultHmacKey(MacAlgorithm algorithm, SessionTicketMacFormat format, byte[] key) {
        this.algorithm = algorithm;
        this.format = format;
        this.key = key;
    }
}
