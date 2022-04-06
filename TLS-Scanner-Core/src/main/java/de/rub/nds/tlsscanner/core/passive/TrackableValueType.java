/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.passive;

import de.rub.nds.scanner.core.passive.TrackableValue;

public enum TrackableValueType implements TrackableValue {
    COOKIE,
    RANDOM,
    SESSION_ID,
    DHE_PUBLICKEY,
    ECDHE_PUBKEY,
    GCM_NONCE_EXPLICIT,
    CBC_IV,
    DTLS_RETRANSMISSIONS,
    DESTINATION_PORT,
}
