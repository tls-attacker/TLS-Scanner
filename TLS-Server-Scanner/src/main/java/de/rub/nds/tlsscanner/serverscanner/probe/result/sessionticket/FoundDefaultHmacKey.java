/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket;

import de.rub.nds.protocol.constants.MacAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketMacFormat;
import java.io.Serializable;

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
