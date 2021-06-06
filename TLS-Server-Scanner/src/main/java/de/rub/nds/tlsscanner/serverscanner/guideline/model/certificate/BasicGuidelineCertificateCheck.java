/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.guideline.model.certificate;

import de.rub.nds.tlsscanner.serverscanner.probe.certificate.CertificateChain;

import java.util.List;

public abstract class BasicGuidelineCertificateCheck implements IGuidelineCertificateCheck {

    @Override
    public final boolean test(List<CertificateChain> certificateChains) {
        int passCount = this.passCount(certificateChains);
        for (CertificateChain chain : certificateChains) {
            boolean result;
            try {
                result = this.checkChain(chain);
            } catch (Throwable ignored) {
                continue;
            }
            if (result) {
                if (--passCount == 0) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Implements the check that will be performed on every chain.
     *
     * @param  chain
     *               the chain.
     * @return       <code>true</code> if it passes the check.
     */
    public abstract boolean checkChain(CertificateChain chain) throws Throwable;

    /**
     * The amount of chains that have to pass the check. Can be used to differentiate between checks have to be passed
     * by all supported certificates or checks that have to be passed by at least one.
     *
     * @param  chains
     *                the chains.
     * @return        the amount of chains that have to pass this check.
     */
    public int passCount(List<CertificateChain> chains) {
        return chains.size();
    }
}
