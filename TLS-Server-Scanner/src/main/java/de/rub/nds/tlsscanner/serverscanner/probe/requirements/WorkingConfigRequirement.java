/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.probe.requirements;

import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsscanner.serverscanner.selector.ConfigSelector;

/** Represents a {@link Requirement} for the requirement of a working config. */
public class WorkingConfigRequirement extends Requirement {

    private ConfigSelector configSelector;

    /**
     * @param configSelector the ConfigSelector.
     */
    public WorkingConfigRequirement(ConfigSelector configSelector) {
        super();
        this.configSelector = configSelector;
    }

    @Override
    protected boolean evaluateInternal(ScanReport report) {
        if (configSelector == null) {
            return false;
        }
        return configSelector.foundWorkingConfig();
    }

    @Override
    public String toString() {
        return "WorkingConfig";
    }

    @Override
    public Requirement getMissingRequirementIntern(Requirement missing, ScanReport report) {
        if (evaluateInternal(report) == false) {
            return next.getMissingRequirementIntern(
                    missing.requires(new WorkingConfigRequirement(configSelector)), report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }

    @Override
    public Enum<?>[] getRequirement() {
        return new Enum<?>[] {SpecialRequirementTypes.WORKING_CONFIG};
    }
}
