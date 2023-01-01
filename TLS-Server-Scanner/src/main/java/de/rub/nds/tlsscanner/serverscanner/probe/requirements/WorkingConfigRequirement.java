
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
            return next.getMissingRequirementIntern(missing.requires(new WorkingConfigRequirement(configSelector)),
                report);
        }
        return next.getMissingRequirementIntern(missing, report);
    }
}
