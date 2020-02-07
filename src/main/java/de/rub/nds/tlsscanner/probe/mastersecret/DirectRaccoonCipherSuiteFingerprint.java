/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe.mastersecret;

import de.rub.nds.tlsattacker.attacks.util.response.EqualityError;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.List;

/**
 *
 * @author Nurullah Erinola - nurullah.erinola@rub.de
 */
public class DirectRaccoonCipherSuiteFingerprint {

    private final Boolean vulnerable;
    private final ProtocolVersion version;
    private final CipherSuite suite;
    private final List<List<VectorResponse>> responseMapList;
    private Boolean handshakeIsWorking;

    private final EqualityError equalityError;
    private final boolean shakyScans;
    private final boolean hasScanningError;

    public DirectRaccoonCipherSuiteFingerprint(Boolean vulnerable, ProtocolVersion version, CipherSuite suite, List<List<VectorResponse>> responseMapList, EqualityError equalityError, boolean shakyScans, boolean hasScanningError) {
        this.vulnerable = vulnerable;
        this.version = version;
        this.suite = suite;
        this.responseMapList = responseMapList;
        this.equalityError = equalityError;
        this.shakyScans = shakyScans;
        this.hasScanningError = hasScanningError;
        handshakeIsWorking = null;
    }

    public Boolean getHandshakeIsWorking() {
        return handshakeIsWorking;
    }

    public void setHandshakeIsWorking(Boolean handshakeIsWorking) {
        this.handshakeIsWorking = handshakeIsWorking;
    }

    public boolean isShakyScans() {
        return shakyScans;
    }

    public boolean isHasScanningError() {
        return hasScanningError;
    }

    public Boolean getVulnerable() {
        return vulnerable;
    }

    public List<List<VectorResponse>> getResponseMapList() {
        return responseMapList;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public CipherSuite getSuite() {
        return suite;
    }

    public EqualityError getEqualityError() {
        return equalityError;
    }
}
