/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.namedgroup;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import org.junit.jupiter.api.Test;

class NamedGroupWitnessTest {

    @Test
    void testSetCertificateGroup() {
        NamedGroupWitness witness = new NamedGroupWitness();
        X509NamedCurve expectedCurve = X509NamedCurve.SECP256R1;

        witness.setCertificateGroup(expectedCurve);

        assertEquals(expectedCurve, witness.getCertificateGroup());
    }

    @Test
    void testSetEcdhPublicKeyGroup() {
        NamedGroupWitness witness = new NamedGroupWitness();
        NamedGroup expectedGroup = NamedGroup.SECP256R1;

        witness.setEcdhPublicKeyGroup(expectedGroup);

        assertEquals(expectedGroup, witness.getEcdhPublicKeyGroup());
    }

    @Test
    void testConstructorWithCipherSuite() {
        CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
        NamedGroupWitness witness = new NamedGroupWitness(cipherSuite);

        assertNotNull(witness.getCipherSuites());
        assertEquals(1, witness.getCipherSuites().size());
        assertEquals(cipherSuite, witness.getCipherSuites().iterator().next());
    }

    @Test
    void testConstructorWithAllParameters() {
        NamedGroup ecdhGroup = NamedGroup.SECP384R1;
        X509NamedCurve certGroup = X509NamedCurve.SECP384R1;
        CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;

        NamedGroupWitness witness = new NamedGroupWitness(ecdhGroup, certGroup, cipherSuite);

        assertEquals(ecdhGroup, witness.getEcdhPublicKeyGroup());
        assertEquals(certGroup, witness.getCertificateGroup());
        assertNotNull(witness.getCipherSuites());
        assertEquals(1, witness.getCipherSuites().size());
        assertEquals(cipherSuite, witness.getCipherSuites().iterator().next());
    }
}
