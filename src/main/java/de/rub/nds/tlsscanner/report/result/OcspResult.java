/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.rating.TestResult;
import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.report.SiteReport;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Nils Hanke <nils.hanke@rub.de>
 */
public class OcspResult extends ProbeResult {

    public OcspResult() {
        super(ProbeType.OCSP);
    }

    @Override
    public void mergeData(SiteReport report) {
    }

}
