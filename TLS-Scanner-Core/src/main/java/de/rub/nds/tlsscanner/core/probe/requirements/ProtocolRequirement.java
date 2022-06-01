/**
 * TLS-Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.List;

public class ProtocolRequirement extends Requirement {
    private final ProtocolVersion[] protocols;

    public ProtocolRequirement(ProtocolVersion... protocols) {
        super();
        this.protocols = protocols;
    }

    @Override
    public boolean evaluate(ScanReport report) {
        if (protocols == null || protocols.length == 0)
            return next.evaluate(report);
        @SuppressWarnings("unchecked")
        ListResult<ProtocolVersion> versionsuiteResult =
            (ListResult<ProtocolVersion>) report.getListResult(TlsAnalyzedProperty.LIST_SUPPORTED_PROTOCOLVERSIONS);
        if (versionsuiteResult != null) {
            List<ProtocolVersion> pvList = versionsuiteResult.getList();
            if (pvList != null && !pvList.isEmpty()) {
                for (ProtocolVersion pv : protocols) {
                    if (pvList.contains(pv))
                        return next.evaluate(report);
                }
            }
        }
        return false;
    }

    /**
     * @return the required protocols
     */
    public ProtocolVersion[] getRequirement() {
        return protocols;
    }
}
