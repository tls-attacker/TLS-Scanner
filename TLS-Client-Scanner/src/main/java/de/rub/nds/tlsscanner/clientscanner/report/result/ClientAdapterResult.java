package de.rub.nds.tlsscanner.clientscanner.report.result;

public abstract class ClientAdapterResult {
    public enum EContentShown {
        SHOWN,
        SHOWN_WITH_WARNING,
        SHOWN_AFTER_DISMISSING_WARNING,
        ERROR;

        public boolean wasShown() {
            return !this.equals(ERROR);
        }
    }

    public final EContentShown contentShown;

    public ClientAdapterResult(EContentShown contentShown) {
        this.contentShown = contentShown;
    }

}