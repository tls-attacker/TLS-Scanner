package de.rub.nds.tlsscanner.clientscanner.client;

import java.io.Serializable;
import java.util.Set;

import javax.xml.bind.annotation.XmlSeeAlso;

import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;
import de.rub.nds.tlsscanner.clientscanner.util.helper.UpdatableXmlSeeAlso;

@XmlSeeAlso({}) // this is automated via UpdatableXmlSeeAlso
public abstract class ClientInfo implements Serializable {
    private static Set<Class<?>> seeAlso = UpdatableXmlSeeAlso.patch(ClientProbeResult.class);

    public ClientInfo() {
        seeAlso.add(getClass());
    }

    public abstract String toShortString();
}
