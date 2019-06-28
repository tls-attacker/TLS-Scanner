/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.certificate.CertificateChain;
import de.rub.nds.tlsscanner.report.SiteReport;
import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class CertificateResult extends ProbeResult {

    private boolean expiredCertificates = false;
    private boolean notYetValidCertificates = false;
    private boolean weakHashAlgorithms = false;
    private boolean weakSignatureAlgorithms = false;
    private Certificate certs;
    private CertificateChain chain;

    public CertificateResult(ProbeType type, CertificateChain chain, Certificate certs) {
        super(type);
        this.chain = chain;
        this.certs = certs;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setCertificateChain(chain);
        report.setCertificate(certs);
    }

}
