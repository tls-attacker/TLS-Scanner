/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.tlsscanner.core.constants.ProtocolType;
import de.rub.nds.tlsscanner.core.report.TlsScanReport;

/** Represents a {@link Requirement} of required supported {@link ProtocolType}s. */
public class ProtocolTypeRequirement<ReportT extends TlsScanReport> extends Requirement<ReportT> {

    private final ProtocolType protocolType;

    private final boolean requiredBooleanResult;

    public ProtocolTypeRequirement(boolean requiredBooleanResult, ProtocolType protocolType) {
        this.protocolType = protocolType;
        this.requiredBooleanResult = requiredBooleanResult;
    }

    @Override
    public boolean evaluate(ReportT report) {
        return (report.getProtocolType() == protocolType) == requiredBooleanResult;
    }

    @Override
    public String toString() {
        return String.format(
                "ProtocolTypeRequirement[%s: %s]", requiredBooleanResult, protocolType);
    }
}
