/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.report.result;

import java.io.Serializable;
import java.util.Set;

import javax.xml.bind.annotation.XmlSeeAlso;

import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.util.helper.UpdatableXmlSeeAlso;

@XmlSeeAlso({})
// this is automated via UpdatableXmlSeeAlso
public abstract class ClientProbeResult implements Serializable {
    private static Set<Class<?>> seeAlso = UpdatableXmlSeeAlso.patch(ClientProbeResult.class);

    protected ClientProbeResult() {
        seeAlso.add(getClass());
    }

    public abstract void merge(ClientReport report);

}
