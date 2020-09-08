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
import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CertificateResult extends ProbeResult {

    private List<CertificateChain> certificates;


    public CertificateResult(List<CertificateChain> certificates) {
        super(ProbeType.CERTIFICATE);
        this.certificates = certificates;

    }

    @Override
    public void mergeData(SiteReport report) {
        report.setCertificateChainList(certificates);
    }

}
