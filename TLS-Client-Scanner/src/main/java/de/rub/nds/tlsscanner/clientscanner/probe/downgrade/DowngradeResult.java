/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe.downgrade;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsscanner.clientscanner.probe.Probe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

@XmlAccessorType(XmlAccessType.FIELD)
public class DowngradeResult extends ClientProbeResult {
    private final transient Class<? extends Probe> clazz;
    private final boolean protocolVersionChanged;

    public DowngradeResult(Class<? extends Probe> clazz, ClientHelloMessage chlo1, ClientHelloMessage chlo2) {
        this.clazz = clazz;

        protocolVersionChanged = !getProtocolVersion(chlo1).equals(getProtocolVersion(chlo2));

        // TODO evaluate supported versions
        // TODO evaluate supported ciphersuites - downgrade scsv?
    }

    protected ProtocolVersion getProtocolVersion(ClientHelloMessage chlo) {
        return ProtocolVersion.getProtocolVersion(chlo.getProtocolVersion().getValue());
    }

    @Override
    public void merge(ClientReport report) {
        report.putResult(clazz, this);
    }

}
