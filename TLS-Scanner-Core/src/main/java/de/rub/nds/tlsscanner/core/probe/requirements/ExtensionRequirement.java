package de.rub.nds.tlsscanner.core.probe.requirements;

import de.rub.nds.scanner.core.constants.ListResult;
import de.rub.nds.scanner.core.probe.requirements.Requirement;
import de.rub.nds.scanner.core.report.ScanReport;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import java.util.List;

public class ExtensionRequirement extends Requirement{
	private final ExtensionType[] extensions;
	
	public ExtensionRequirement(ExtensionType... extensions){
		super();
		this.extensions = extensions;
	}
	
	@Override
	public boolean evaluate(ScanReport report) {
		if (extensions == null || extensions.length == 0)
            return next.evaluate(report);
        @SuppressWarnings("unchecked")
        ListResult<ExtensionType> extensionResult =
            (ListResult<ExtensionType>) report.getListResult(TlsAnalyzedProperty.LIST_SUPPORTED_EXTENSIONS);
        if (extensionResult != null) {
            List<ExtensionType> etList = extensionResult.getList();
            if (etList != null && !etList.isEmpty()) {
                for (ExtensionType et : extensions) {
                    if (etList.contains(et))
                        return next.evaluate(report);
                }
            }
        }
        return false;
	}
	
	/**
	 * @return the required extensions
	 */
	public ExtensionType[] getRequirement() {
		return extensions;
	}
}
