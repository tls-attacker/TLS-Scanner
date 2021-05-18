/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.constants;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public enum GcmPattern {
    INCREMENTING,
    RANDOM,
    REPEATING,
    AWKWARD
}
