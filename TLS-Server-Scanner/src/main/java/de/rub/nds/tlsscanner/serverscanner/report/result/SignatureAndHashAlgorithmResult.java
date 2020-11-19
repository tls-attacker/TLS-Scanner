/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class SignatureAndHashAlgorithmResult extends ProbeResult {

    private final List<SignatureAndHashAlgorithm> signatureAndHashAlgorithmList;

    public SignatureAndHashAlgorithmResult(List<SignatureAndHashAlgorithm> signautureAndHashAlgorithmList) {
        super(ProbeType.SIGNATURE_AND_HASH);
        this.signatureAndHashAlgorithmList = signautureAndHashAlgorithmList;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithmList);
    }

}
