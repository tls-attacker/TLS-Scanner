/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.clientscanner.workflow;

import java.io.IOException;

import org.bouncycastle.operator.OperatorCreationException;

import de.rub.nds.tlsattacker.core.state.State;

public interface CertificatePatcher {
    void patchCertificate(State state) throws CertificatePatchException;
}
