/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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
