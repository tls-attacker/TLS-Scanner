/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

public class WorkingConfigRequirement extends Requirement {

    private ConfigSelector configSelector;

    public WorkingConfigRequirement(ConfigSelector configSelector) {
        super();
        this.configSelector = configSelector;
    }

    @Override
    protected boolean evaluateIntern(ScanReport report) {
        if (configSelector == null) {
            return false;
        }
        return configSelector.foundWorkingConfig();
    }

    public boolean getRequirement() {
        if (configSelector == null) {
            return false;
        }
        return configSelector.foundWorkingConfig();
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateIntern(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(new WorkingConfigRequirement(configSelector)), report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
