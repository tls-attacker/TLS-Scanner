/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe.namedcurve;

public enum WitnessType {
    RSA_ONLY,
    RSA_ECSDA_STATIC,
    RSA_ECDSA_EPHEMERAL,
    ECDSA_ONLY,
    ECDSA_STATIC_ONLY,
    ECDSA_EPHEMERAL_ONLY,
    RSA_ECDSA_EPHEMERAL_STATIC, // =ALL but it's easier to evaluate like this
    TLS_13
}
