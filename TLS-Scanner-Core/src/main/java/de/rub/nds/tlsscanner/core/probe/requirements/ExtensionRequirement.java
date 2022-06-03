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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.ArrayList;
import java.util.List;

public class ExtensionRequirement extends Requirement {
    private final ExtensionType[] extensions;
    private List<ExtensionType> missing;

    public ExtensionRequirement(ExtensionType... extensions) {
        super();
        this.extensions = extensions;
        this.missing = new ArrayList<>();
    }

    @Override
    protected boolean evaluateIntern(ScanReport report) {
        if (extensions == null || extensions.length == 0)
            return true;
        boolean returnValue = false;
        missing = new ArrayList<>();
        @SuppressWarnings("unchecked")
        ListResult<ExtensionType> extensionResult =
            (ListResult<ExtensionType>) report.getListResult(TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS);
        if (extensionResult != null) {
            List<ExtensionType> etList = extensionResult.getList();
            if (etList != null && !etList.isEmpty()) {
                for (ExtensionType et : extensions) {
                    if (etList.contains(et))
                        returnValue = true;
                    else
                        missing.add(et);
                }
            }
        } else {
            for (ExtensionType et : extensions)
                missing.add(et);
        }
        return returnValue;
    }

    /**
     * @return the required extensions
     */
    public ExtensionType[] getRequirement() {
        return extensions;
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateIntern(report) == false)
            return next.getMissingRequirementIntern(missing.requires(
                new ExtensionRequirement(this.missing.toArray(new ExtensionType[this.missing.size()]))), report);
        return next.getMissingRequirementIntern(missing, report);
    }
}
