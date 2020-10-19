/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
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