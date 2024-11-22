/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.namedgroup;

import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

public class NamedGroupWitness implements Serializable {

    private Set<CipherSuite> cipherSuites;

    // the curve used in the ephemeral key exchange
    private NamedGroup ecdhPublicKeyGroup;

    // the curve used to sign the cert that bears the server's signing key
    private X509NamedCurve certificateGroup;

    public NamedGroupWitness() {
        cipherSuites = new HashSet<>();
    }

    public NamedGroupWitness(
            NamedGroup ecdhPublicKeyGroup,
            X509NamedCurve ecdsaCertificateGroup,
            CipherSuite cipherSuite) {
        this.ecdhPublicKeyGroup = ecdhPublicKeyGroup;
        this.certificateGroup = ecdsaCertificateGroup;
        cipherSuites = new HashSet<>();
        cipherSuites.add(cipherSuite);
    }

    public NamedGroupWitness(CipherSuite cipherSuite) {
        cipherSuites = new HashSet<>();
        cipherSuites.add(cipherSuite);
    }

    public NamedGroup getEcdhPublicKeyGroup() {
        return ecdhPublicKeyGroup;
    }

    public X509NamedCurve getCertificateGroup() {
        return certificateGroup;
    }

    public boolean isFoundUsingRsaCipher() {
        for (CipherSuite cipherSuite : cipherSuites) {
            if (!cipherSuite.isTLS13()
                    && AlgorithmResolver.getRequiredSignatureAlgorithm(cipherSuite)
                            == SignatureAlgorithm.RSA_PKCS1) {
                return true;
            }
        }
        return false;
    }

    public boolean isFoundUsingEcdsaStaticCipher() {
        for (CipherSuite cipherSuite : cipherSuites) {
            if (!cipherSuite.isTLS13()
                    && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)
                            == KeyExchangeAlgorithm.ECDH_ECDSA) {
                return true;
            }
        }
        return false;
    }

    public boolean isFoundUsingEcdsaEphemeralCipher() {
        for (CipherSuite cipherSuite : cipherSuites) {
            if (!cipherSuite.isTLS13()
                    && AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite)
                            == KeyExchangeAlgorithm.ECDHE_ECDSA) {
                return true;
            }
        }
        return false;
    }

    public void setEcdhPublicKeyGroup(NamedGroup ecdsaPkGroupEphemeral) {
        this.ecdhPublicKeyGroup = ecdsaPkGroupEphemeral;
    }

    public void setCertificateGroup(X509NamedCurve ecdsaSigGroupStatic) {
        this.certificateGroup = certificateGroup;
    }

    public Set<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(Set<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }
}
