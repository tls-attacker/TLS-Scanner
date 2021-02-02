package de.rub.nds.tlsscanner.clientscanner.workflow;

import java.io.IOException;

import org.bouncycastle.operator.OperatorCreationException;

import de.rub.nds.tlsattacker.core.state.State;

public interface CertificatePatcher {
    void patchCertificate(State state) throws CertificatePatchException;
}
