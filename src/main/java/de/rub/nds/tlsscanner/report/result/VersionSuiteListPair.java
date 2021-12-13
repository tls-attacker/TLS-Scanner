/*
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.List;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class VersionSuiteListPair {

    private final ProtocolVersion version;

    private final List<CipherSuite> ciphersuiteList;

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
