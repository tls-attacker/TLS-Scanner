/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket;

import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionTicketEncryptionFormat;
import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.TicketEncryptionAlgorithm;
import java.io.Serializable;

public class FoundDefaultStek implements Serializable {
    public final TicketEncryptionAlgorithm algorithm;
    public final SessionTicketEncryptionFormat format;
    public final byte[] key;
    public final FoundSecret secret;

    public FoundDefaultStek(
            TicketEncryptionAlgorithm algorithm,
            SessionTicketEncryptionFormat format,
            byte[] key,
            FoundSecret secret) {
        this.algorithm = algorithm;
        this.format = format;
        this.key = key;
        this.secret = secret;
    }
}
