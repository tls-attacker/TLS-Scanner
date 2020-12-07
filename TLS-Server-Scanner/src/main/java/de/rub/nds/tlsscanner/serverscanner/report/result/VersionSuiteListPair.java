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

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.List;

/**
 *
 * @author Robert Merget {@literal <robert.merget@rub.de>}
 */
public class VersionSuiteListPair {

    private final ProtocolVersion version;

    private final List<CipherSuite> cipherSuiteList;

    private VersionSuiteListPair() {
        version = null;
        cipherSuiteList = null;
    }

    public VersionSuiteListPair(ProtocolVersion version, List<CipherSuite> cipherSuiteList) {
        this.version = version;
        this.cipherSuiteList = cipherSuiteList;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public List<CipherSuite> getCipherSuiteList() {
        return cipherSuiteList;
    }

}
