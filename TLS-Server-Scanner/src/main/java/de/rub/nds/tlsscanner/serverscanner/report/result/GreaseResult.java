/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;

public class GreaseResult extends ProbeResult {

    private final TestResult greaseCipherSuiteTolerated;
    private final TestResult greaseNamedGroupTolerated;
    private final TestResult greaseSignatureAndHashAlgorithmTolerated;

    public GreaseResult(TestResult greaseCipherTolerated, TestResult greaseNamedGroupTolerated,
            TestResult greaseSignatureAndHashAlgorithmTolerated) {
        super(ProbeType.GREASE);
        this.greaseCipherSuiteTolerated = greaseCipherTolerated;
        this.greaseNamedGroupTolerated = greaseNamedGroupTolerated;
        this.greaseSignatureAndHashAlgorithmTolerated = greaseSignatureAndHashAlgorithmTolerated;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.putResult(AnalyzedProperty.TOLERATES_GREASE_CIPHER_SUITE, greaseCipherSuiteTolerated);
        report.putResult(AnalyzedProperty.TOLERATES_GREASE_NAMED_GROUP, greaseNamedGroupTolerated);
        report.putResult(AnalyzedProperty.TOLERATES_GREASE_SIGNATURE_AND_HASH_ALGORITHM,
                greaseSignatureAndHashAlgorithmTolerated);
    }

}
