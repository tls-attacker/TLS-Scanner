/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.List;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class SignatureAndHashAlgorithmResult extends ProbeResult {

    private final List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmList;

    public SignatureAndHashAlgorithmResult(List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmList) {
        super(ProbeType.SIGNATURE_AND_HASH);
        this.signatureAndHashAlgorithmList = signatureAndHashAlgorithmList;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithmList);
    }

}
