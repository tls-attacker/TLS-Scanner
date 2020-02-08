/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.directRaccoon;

import de.rub.nds.tlsattacker.attacks.util.response.ResponseFingerprint;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class VectorResponse {
    
    private final ResponseFingerprint fingerprint;

    private final DirectRaccoonWorkflowType type;

    private final ProtocolVersion version;

    private final CipherSuite suite;
    
    private final boolean pmsWithNullByte;
    
    private boolean shaky = false;

    private boolean missingEquivalent = false;
    
    private boolean errorDuringHandshake = false;
    
    public VectorResponse (ResponseFingerprint fingerprint, DirectRaccoonWorkflowType type, ProtocolVersion version, CipherSuite suite, boolean pmsWithNullByte) {
        this.fingerprint = fingerprint;
        this.type = type;
        this.version = version;
        this.suite = suite;
        this.pmsWithNullByte = pmsWithNullByte;
    }
       
    public boolean isErrorDuringHandshake() {
        return errorDuringHandshake;
    }

    public void setErrorDuringHandshake(boolean errorDuringHandshake) {
        this.errorDuringHandshake = errorDuringHandshake;
    }
    
    public boolean isShaky() {
        return shaky;
    }

    public void setShaky(boolean shaky) {
        this.shaky = shaky;
    }    

    public boolean isMissingEquivalent() {
        return missingEquivalent;
    }

    public void setMissingEquivalent(boolean missingEquivalent) {
        this.missingEquivalent = missingEquivalent;
    }
    
    public boolean isPmsWithNullybte() {
        return pmsWithNullByte;
    }
    
    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    public DirectRaccoonWorkflowType getWorkflowType() {
        return type;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public CipherSuite getSuite() {
        return suite;
    }

    @Override
    public String toString() {
        return "VectorResponse{" + "fingerprint=" + fingerprint + ", WorkflowType=" + type + ", version="
                + version + ", suite=" + suite + ", pmsWithNullByte=" + pmsWithNullByte + '}';
    }
}
