package de.rub.nds.tlsscanner.clientscanner.report.result;

import java.io.Serializable;
import java.util.Set;

import javax.xml.bind.annotation.XmlSeeAlso;

import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;
import de.rub.nds.tlsscanner.clientscanner.util.helper.UpdatableXmlSeeAlso;

@XmlSeeAlso({}) // this is automated via UpdatableXmlSeeAlso
public abstract class ClientProbeResult implements Serializable {
    private static Set<Class<?>> seeAlso = UpdatableXmlSeeAlso.patch(ClientProbeResult.class);

    public ClientProbeResult() {
        seeAlso.add(getClass());
    }

    public abstract void merge(ClientReport report);

}
