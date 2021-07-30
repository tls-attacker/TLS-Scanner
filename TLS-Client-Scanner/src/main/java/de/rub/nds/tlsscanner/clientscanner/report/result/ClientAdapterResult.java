/**
 * TLS-Client-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
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