/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.scanner.core.guideline.GuidelineAdherence;
import de.rub.nds.scanner.core.guideline.GuidelineCheckResult;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;

public class CertificateSignatureCheckResult extends GuidelineCheckResult {

    private final X509PublicKeyType keyAlgorithm;
    private final SignatureAlgorithm signatureAlgorithm;

    public CertificateSignatureCheckResult(
            String checkName,
            GuidelineAdherence adherence,
            X509PublicKeyType keyAlgorithm,
            SignatureAlgorithm signatureAlgorithm) {
        super(checkName, adherence);
        this.keyAlgorithm = keyAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public String toString() {
        return keyAlgorithm + " key is signed with " + signatureAlgorithm;
    }

    public X509PublicKeyType getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
}
