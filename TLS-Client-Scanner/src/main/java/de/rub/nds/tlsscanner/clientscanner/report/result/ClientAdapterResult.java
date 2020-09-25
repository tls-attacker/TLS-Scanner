package de.rub.nds.tlsscanner.clientscanner.report.result;

public abstract class ClientAdapterResult {
    public enum EContentShown {
        SHOWN,
        SHOWN_WITH_WARNING,
        SHOWN_AFTER_DISMISSING_WARNING,
        ERROR,
    }

    private EContentShown contentShown;

}