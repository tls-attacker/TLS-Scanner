/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

import java.io.Serializable;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class VersionSuiteListPair implements Serializable {

    private final ProtocolVersion version;

    private final List<CipherSuite> ciphersuiteList;

    private VersionSuiteListPair() {
        version = null;
        ciphersuiteList = null;
    }

    public VersionSuiteListPair(ProtocolVersion version, List<CipherSuite> ciphersuiteList) {
        this.version = version;
        this.ciphersuiteList = ciphersuiteList;
    }

    public ProtocolVersion getVersion() {
        return version;
    }

    public List<CipherSuite> getCiphersuiteList() {
        return ciphersuiteList;
    }

}
