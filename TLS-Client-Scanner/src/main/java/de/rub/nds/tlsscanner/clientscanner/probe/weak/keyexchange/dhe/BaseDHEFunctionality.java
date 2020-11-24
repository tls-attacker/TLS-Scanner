/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.clientscanner.probe.weak.keyexchange.dhe;

import java.util.ArrayList;
import java.util.List;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SupportedCipherSuitesProbe;
import de.rub.nds.tlsscanner.clientscanner.probe.recon.SupportedCipherSuitesProbe.SupportedCipherSuitesResult;
import de.rub.nds.tlsscanner.clientscanner.report.requirements.ProbeRequirements;

class BaseDHEFunctionality {
    private BaseDHEFunctionality() {
        throw new UnsupportedOperationException("Utility class");
    }

    private static List<CipherSuite> ffdhe_suites;
    private static List<CipherSuite> ecdhe_suites;
    private static List<CipherSuite> tls13_suites;

    static {
        ffdhe_suites = new ArrayList<>();
        ecdhe_suites = new ArrayList<>();
        tls13_suites = new ArrayList<>();
        for (CipherSuite cs : CipherSuite.values()) {
            if (cs.isTLS13()) {
                tls13_suites.add(cs);
            } else {
                String n = cs.name();
                if (n.contains("_DHE_")) {
                    ffdhe_suites.add(cs);
                } else if (n.contains("_ECDHE_")) {
                    ecdhe_suites.add(cs);
                }
            }
        }
    }

    public static ProbeRequirements getRequirements(boolean tls13, boolean ec, boolean ff) {
        return ProbeRequirements.TRUE()
                .needResultOfTypeMatching(
                        SupportedCipherSuitesProbe.class,
                        SupportedCipherSuitesResult.class,
                        r -> r.supportsKeyExchangeDHE(tls13, ec, ff),
                        "Client does not support DHE key exchange");
    }

    public static void prepareConfig(Config config, boolean tls13, boolean ec, boolean ff) {
        List<CipherSuite> suites = new ArrayList<>();
        if (ec) {
            suites.addAll(ecdhe_suites);
        }
        if (ff) {
            suites.addAll(ffdhe_suites);
        }
        // if we add tls13 suites first, the ServerHelloPreparator will try to
        // choose
        // these first. But these suites are invalid in 1.2
        if (tls13) {
            suites.addAll(tls13_suites);
        }
        config.setDefaultServerSupportedCiphersuites(suites);
        config.setDefaultSelectedCipherSuite(suites.get(0));
    }

}
