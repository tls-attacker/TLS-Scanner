/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.result.sessionticket;

import de.rub.nds.tlsscanner.serverscanner.probe.sessionticket.SessionSecret;
import java.io.Serializable;

public class FoundSecret implements Serializable {
    public final SessionSecret secret;
    /** Offset of the secret in the ticket (from left; 0=start). */
    public final int offset;

    public FoundSecret(SessionSecret secret, int offset) {
        this.secret = secret;
        this.offset = offset;
    }

    public String toReportString() {
        return secret.secretType.toString() + " at offset " + offset;
    }
}
