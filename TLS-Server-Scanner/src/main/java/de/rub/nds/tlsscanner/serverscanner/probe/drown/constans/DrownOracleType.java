/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.drown.constans;

/** Represents different types of oracles that can be exploited in DROWN attacks. */
public enum DrownOracleType {
    /** Oracle based on extra clear messages in SSLv2 protocol. */
    EXTRA_CLEAR,
    /** Oracle based on leaky export cipher suites. */
    LEAKY_EXPORT
}
