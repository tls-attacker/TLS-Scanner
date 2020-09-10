/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.probe.namedcurve;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;

public class NamedCurveWitness {
    private WitnessType witnessType;

    // the curves used to generate an ecdsa sig inside the key ex. message
    private final NamedGroup ecdsaPkGroupStatic;
    private final NamedGroup ecdsaPkGroupEphemeral;

    // the curve used to sign the cert that bears the server's signing key
    private final NamedGroup ecdsaSigGroupStatic;
    private final NamedGroup ecdsaSigGroupEphemeral;

    public NamedCurveWitness(WitnessType witnessType, NamedGroup ecdsaPkGroupStatic, NamedGroup ecdsaPkGroupEphemeral,
            NamedGroup ecdsaSigGroupStatic, NamedGroup ecdsaSigGroupEphemeral) {
        this.witnessType = witnessType;
        this.ecdsaPkGroupStatic = ecdsaPkGroupStatic;
        this.ecdsaPkGroupEphemeral = ecdsaPkGroupEphemeral;
        this.ecdsaSigGroupStatic = ecdsaSigGroupStatic;
        this.ecdsaSigGroupEphemeral = ecdsaSigGroupEphemeral;
    }

    public WitnessType getWitnessType() {
        return witnessType;
    }

    public void setWitnessType(WitnessType witnessType) {
        this.witnessType = witnessType;
    }

    public NamedGroup getEcdsaPkGroupStatic() {
        return ecdsaPkGroupStatic;
    }

    public NamedGroup getEcdsaPkGroupEphemeral() {
        return ecdsaPkGroupEphemeral;
    }

    public NamedGroup getEcdsaSigGroupStatic() {
        return ecdsaSigGroupStatic;
    }

    public NamedGroup getEcdsaSigGroupEphemeral() {
        return ecdsaSigGroupEphemeral;
    }

}
