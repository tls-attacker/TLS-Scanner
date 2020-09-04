package de.rub.nds.tlsscanner.clientscanner.report.result;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlTransient;

import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;

@XmlAccessorType(XmlAccessType.FIELD)
public class NotExecutedResult extends ClientProbeResult {
    @XmlTransient
    private final Class<? extends IProbe> probe;
    public final String message;

    public NotExecutedResult(Class<? extends IProbe> probe, String message) {
        this.probe = probe;
        this.message = message;
    }

    @Override
    public void merge(ClientReport report) {
        report.putResult(probe, this);
    }

}
