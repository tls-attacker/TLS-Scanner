/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.guideline.results;

import de.rub.nds.scanner.core.constants.TestResult;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsscanner.core.guideline.GuidelineCheckResult;

public class CertificateSignatureCheckResult extends GuidelineCheckResult {

    private final String keyAlgorithm;
    private final SignatureAlgorithm signatureAlgorithm;

    public CertificateSignatureCheckResult(
            TestResult result, String keyAlgorithm, SignatureAlgorithm signatureAlgorithm) {
        super(result);
        this.keyAlgorithm = keyAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public String display() {
        return keyAlgorithm + " key is signed with " + signatureAlgorithm;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
}
