/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.cca.vector;

import de.rub.nds.tlsscanner.serverscanner.task.CcaTask;

public class CcaTaskVectorPair {

    private final CcaTask ccaTask;

    private final CcaVector ccaVector;

    public CcaTaskVectorPair(CcaTask ccaTask, CcaVector vector) {
        this.ccaTask = ccaTask;
        this.ccaVector = vector;
    }

    public CcaTask getCcaTask() {
        return ccaTask;
    }

    public CcaVector getVector() {
        return ccaVector;
    }

    @Override
    public String toString() {
        return "CcaProbeTaskVectorPair{" + "ccaTask=" + ccaTask + ", vector=" + ccaVector + '}';
    }
}
