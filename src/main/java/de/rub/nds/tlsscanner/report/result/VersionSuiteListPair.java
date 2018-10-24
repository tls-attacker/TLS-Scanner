/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
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
