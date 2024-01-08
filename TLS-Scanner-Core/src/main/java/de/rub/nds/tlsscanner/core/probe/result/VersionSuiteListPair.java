/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.result;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.io.Serializable;
import java.util.List;

public class VersionSuiteListPair implements Serializable {

    private final ProtocolVersion version;

    private final List<CipherSuite> cipherSuiteList;

    /** Private no-arg constructor to please JAXB */
    @SuppressWarnings("unused")
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
