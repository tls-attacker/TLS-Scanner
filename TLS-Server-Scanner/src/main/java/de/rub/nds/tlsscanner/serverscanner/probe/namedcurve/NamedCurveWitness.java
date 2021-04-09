/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.probe.namedcurve;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CertificateKeyType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

public class NamedCurveWitness implements Serializable {

    private Set<CipherSuite> cipherSuites;

    // the curves used to generate an ecdsa sig inside the key ex. message
    private NamedGroup ecdsaPkGroupEphemeral;

    // the curve used to sign the cert that bears the server's signing key
    private NamedGroup ecdsaSigGroupStatic;
    private NamedGroup ecdsaSigGroupEphemeral;

    public NamedCurveWitness() {
        cipherSuites = new HashSet<>();
    }

    public NamedCurveWitness(NamedGroup ecdsaPkGroupEphemeral, NamedGroup ecdsaSigGroupStatic,
        NamedGroup ecdsaSigGroupEphemeral, CipherSuite cipherSuite) {
        this.ecdsaPkGroupEphemeral = ecdsaPkGroupEphemeral;
        this.ecdsaSigGroupStatic = ecdsaSigGroupStatic;
        this.ecdsaSigGroupEphemeral = ecdsaSigGroupEphemeral;
        cipherSuites = new HashSet<>();
        cipherSuites.add(cipherSuite);
    }

    public NamedCurveWitness(CipherSuite cipherSuite) {
        cipherSuites = new HashSet<>();
        cipherSuites.add(cipherSuite);
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
        for (CipherSuite cipherSuite : cipherSuites) {
            if (!cipherSuite.isTLS13()
                && AlgorithmResolver.getCertificateKeyType(cipherSuite) == CertificateKeyType.RSA) {
                return true;
            }
        }
        return false;
    }

    public boolean isFoundUsingEcdsaStaticCipher() {
        for (CipherSuite cipherSuite : cipherSuites) {
            if (!cipherSuite.isTLS13()
                && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.ECDH_ECDSA) {
                return true;
            }
        }
        return false;
    }

    public boolean isFoundUsingEcdsaEphemeralCipher() {
        for (CipherSuite cipherSuite : cipherSuites) {
            if (!cipherSuite.isTLS13()
                && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite) == KeyExchangeAlgorithm.ECDHE_ECDSA) {
                return true;
            }
        }
        return false;
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

    public Set<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(Set<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

}
