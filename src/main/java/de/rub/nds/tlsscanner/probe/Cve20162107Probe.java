/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.probe;

import de.rub.nds.tlsattacker.attacks.config.Cve20162107CommandConfig;
import de.rub.nds.tlsattacker.attacks.impl.Cve20162107Attacker;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.ProbeResult;
import de.rub.nds.tlsscanner.report.ResultValue;
import de.rub.nds.tlsscanner.report.check.CheckType;
import de.rub.nds.tlsscanner.report.check.TLSCheck;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class Cve20162107Probe extends TLSProbe {

    public Cve20162107Probe(ScannerConfig config) {
        super(ProbeType.CVE20162107, config);
    }

    @Override
    public ProbeResult call() {
        LOGGER.debug("Starting Cve20162107 Probe");
        Cve20162107CommandConfig poodleCommandConfig = new Cve20162107CommandConfig(getScannerConfig().getGeneralDelegate());
        ClientDelegate delegate = (ClientDelegate) poodleCommandConfig.getDelegate(ClientDelegate.class);
        delegate.setHost(getScannerConfig().getClientDelegate().getHost());
        Cve20162107Attacker attacker = new Cve20162107Attacker(poodleCommandConfig);
        Boolean vulnerable = attacker.isVulnerable();
        TLSCheck check = new TLSCheck(vulnerable, CheckType.ATTACK_CVE20162107, 10);
        List<TLSCheck> checkList = new LinkedList<>();
        checkList.add(check);
        return new ProbeResult(getType(), new LinkedList<ResultValue>(), checkList);
    }

}
