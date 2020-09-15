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
    private boolean foundUsingRsaCipher = false;
    private boolean foundUsingEcdsaStaticCipher = false;
    private boolean foundUsingEcdsaEphemeralCipher = false;

    // the curves used to generate an ecdsa sig inside the key ex. message
    private NamedGroup ecdsaPkGroupStatic;
    private NamedGroup ecdsaPkGroupEphemeral;

    // the curve used to sign the cert that bears the server's signing key
    private NamedGroup ecdsaSigGroupStatic;
    private NamedGroup ecdsaSigGroupEphemeral;

    public NamedCurveWitness() {

    }

    public NamedCurveWitness(NamedGroup ecdsaPkGroupStatic, NamedGroup ecdsaPkGroupEphemeral,
            NamedGroup ecdsaSigGroupStatic, NamedGroup ecdsaSigGroupEphemeral) {
        this.ecdsaPkGroupStatic = ecdsaPkGroupStatic;
        this.ecdsaPkGroupEphemeral = ecdsaPkGroupEphemeral;
        this.ecdsaSigGroupStatic = ecdsaSigGroupStatic;
        this.ecdsaSigGroupEphemeral = ecdsaSigGroupEphemeral;
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

    public boolean isFoundUsingRsaCipher() {
        return foundUsingRsaCipher;
    }

    public void setFoundUsingRsaCipher(boolean foundUsingRsaCipher) {
        this.foundUsingRsaCipher = foundUsingRsaCipher;
    }

    public boolean isFoundUsingEcdsaStaticCipher() {
        return foundUsingEcdsaStaticCipher;
    }

    public void setFoundUsingEcdsaStaticCipher(boolean foundUsingEcdsaStaticCipher) {
        this.foundUsingEcdsaStaticCipher = foundUsingEcdsaStaticCipher;
    }

    public boolean isFoundUsingEcdsaEphemeralCipher() {
        return foundUsingEcdsaEphemeralCipher;
    }

    public void setFoundUsingEcdsaEphemeralCipher(boolean foundUsingEcdsaEphemeralCipher) {
        this.foundUsingEcdsaEphemeralCipher = foundUsingEcdsaEphemeralCipher;
    }

    public void setEcdsaPkGroupStatic(NamedGroup ecdsaPkGroupStatic) {
        this.ecdsaPkGroupStatic = ecdsaPkGroupStatic;
    }

    public void setEcdsaPkGroupEphemeral(NamedGroup ecdsaPkGroupEphemeral) {
        this.ecdsaPkGroupEphemeral = ecdsaPkGroupEphemeral;
    }

    public void setEcdsaSigGroupStatic(NamedGroup ecdsaSigGroupStatic) {
        this.ecdsaSigGroupStatic = ecdsaSigGroupStatic;
    }

    public void setEcdsaSigGroupEphemeral(NamedGroup ecdsaSigGroupEphemeral) {
        this.ecdsaSigGroupEphemeral = ecdsaSigGroupEphemeral;
    }

}
