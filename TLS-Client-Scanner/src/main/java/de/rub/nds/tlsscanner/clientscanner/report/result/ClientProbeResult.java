package de.rub.nds.tlsscanner.clientscanner.report.result;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlSeeAlso;

import de.rub.nds.tlsscanner.clientscanner.probe.CipherSuiteReconProbe.CipherSuiteReconResult;
import de.rub.nds.tlsscanner.clientscanner.probe.SNIProbe.SNIProbeResult;
import de.rub.nds.tlsscanner.clientscanner.probe.VersionProbe.VersionProbeResult;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHMinimumModulusLengthProbe.DHMinimumModulusLengthResult;
import de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe.DHWeakPrivateKeyProbe.DHWeakPrivateKeyProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;

@XmlSeeAlso({
        NotExecutedResult.class,
        VersionProbeResult.class,
        SNIProbeResult.class,
        CipherSuiteReconResult.class,
        DHWeakPrivateKeyProbeResult.class,
        DHMinimumModulusLengthResult.class,
})
public abstract class ClientProbeResult implements Serializable {
    public abstract void merge(ClientReport report);

}