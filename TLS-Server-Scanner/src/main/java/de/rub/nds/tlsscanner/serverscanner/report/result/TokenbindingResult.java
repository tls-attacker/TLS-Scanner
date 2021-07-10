/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report.result;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsscanner.serverscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.serverscanner.rating.TestResult;
import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import de.rub.nds.tlsscanner.serverscanner.report.SiteReport;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author robert
 */
public class TokenbindingResult extends ProbeResult {

    private List<TokenBindingVersion> supportedTokenBindingVersion = null;
    private List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters = null;

    public TokenbindingResult(List<TokenBindingVersion> supportedTokenBindingVersion,
        List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters) {
        super(ProbeType.TOKENBINDING);
        this.supportedTokenBindingVersion = supportedTokenBindingVersion;
        this.supportedTokenBindingKeyParameters = supportedTokenBindingKeyParameters;
    }

    @Override
    public void mergeData(SiteReport report) {
        report.setSupportedTokenBindingKeyParameters(supportedTokenBindingKeyParameters);
        report.setSupportedTokenBindingVersion(supportedTokenBindingVersion);
        if (supportedTokenBindingVersion != null && !supportedTokenBindingVersion.isEmpty()) {
            report.putResult(AnalyzedProperty.SUPPORTS_TOKENBINDING, TestResult.TRUE);
            if (report.getSupportedExtensions() == null) {
                report.setSupportedExtensions(new LinkedList<ExtensionType>());
            }
            report.getSupportedExtensions().add(ExtensionType.TOKEN_BINDING);
        } else {
            report.putResult(AnalyzedProperty.SUPPORTS_TOKENBINDING, TestResult.FALSE);
        }
    }
}
