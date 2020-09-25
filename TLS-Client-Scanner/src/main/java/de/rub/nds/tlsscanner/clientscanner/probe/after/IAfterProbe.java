package de.rub.nds.tlsscanner.clientscanner.probe.after;

import de.rub.nds.tlsscanner.clientscanner.report.ClientReport;

public interface IAfterProbe {
    public void analyze(ClientReport report);
}
