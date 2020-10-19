/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe.downgrade;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsscanner.clientscanner.probe.BaseStatefulProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.IProbe;
import de.rub.nds.tlsscanner.clientscanner.report.result.ClientProbeResult;

public class DowngradeInternalState implements BaseStatefulProbe.InternalProbeState {
    protected ClientHelloMessage firstCHLO;
    protected ClientHelloMessage secondCHLO;
    protected final Class<? extends IProbe> clazz;

    public DowngradeInternalState(Class<? extends IProbe> clazz) {
        this.clazz = clazz;
    }

    public void putCHLO(ClientHelloMessage chlo) {
        if (!isFirstDone()) {
            firstCHLO = chlo;
        } else if (!isDone()) {
            secondCHLO = chlo;
        } else {
            throw new IllegalStateException("Got more than two client hellos");
        }
    }

    public boolean isFirstDone() {
        return firstCHLO != null;
    }

    @Override
    public boolean isDone() {
        return firstCHLO != null && secondCHLO != null;
    }

    @Override
    public ClientProbeResult toResult() {
        return new DowngradeResult(clazz, firstCHLO, secondCHLO);
    }
}
