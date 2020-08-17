package de.rub.nds.tlsscanner.clientscanner.report.result;

import java.io.Serializable;

import javax.xml.bind.annotation.XmlSeeAlso;

import de.rub.nds.tlsscanner.clientscanner.probe.SNIProbe.SNIProbeResult;
import de.rub.nds.tlsscanner.clientscanner.probe.VersionProbe.VersionProbeResult;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;

@XmlSeeAlso({ VersionProbeResult.class, SNIProbeResult.class })
public abstract class ClientProbeResult implements Serializable {

    public abstract String getProbeName();

    public abstract void merge(ClientReport report);

}