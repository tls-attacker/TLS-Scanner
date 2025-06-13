/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.core.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class VersionInformation {

    private static final String TLS_SCANNER_VERSION;
    private static final String TLS_ATTACKER_VERSION;
    private static final String JAVA_VERSION;

    static {
        // Load TLS-Scanner version from Maven properties
        TLS_SCANNER_VERSION =
                loadVersionFromProperties(
                        "tls-scanner-version.properties", "tls.scanner.version", "unknown");

        // Load TLS-Attacker version from Maven properties
        TLS_ATTACKER_VERSION =
                loadVersionFromProperties(
                        "tls-attacker-version.properties", "tls.attacker.version", "unknown");

        // Get Java version and vendor
        JAVA_VERSION =
                System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ")";
    }

    private static String loadVersionFromProperties(
            String resourceName, String propertyKey, String defaultValue) {
        try (InputStream is =
                VersionInformation.class.getClassLoader().getResourceAsStream(resourceName)) {
            if (is != null) {
                Properties props = new Properties();
                props.load(is);
                return props.getProperty(propertyKey, defaultValue);
            }
        } catch (IOException e) {
            // Fall back to default if properties can't be loaded
        }
        return defaultValue;
    }

    public static String getTlsScannerVersion() {
        return TLS_SCANNER_VERSION;
    }

    public static String getTlsAttackerVersion() {
        return TLS_ATTACKER_VERSION;
    }

    public static String getJavaVersion() {
        return JAVA_VERSION;
    }

    public static String getFullVersionInfo() {
        return String.format(
                "TLS-Scanner %s (TLS-Attacker %s, Java %s)",
                TLS_SCANNER_VERSION, TLS_ATTACKER_VERSION, JAVA_VERSION);
    }
}
