/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.constants;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public enum AnsiColor {
    ANSI_RESET("\u001B[0m"),
    ANSI_BLACK("\u001B[30m"),
    ANSI_RED("\u001B[31m"),
    ANSI_GREEN("\u001B[32m"),
    ANSI_YELLOW("\u001B[33m"),
    ANSI_BLUE("\u001B[34m"),
    ANSI_PURPLE("\u001B[35m"),
    ANSI_CYAN("\u001B[36m"),
    ANSI_WHITE("\u001B[37m"),
    ANSI_BLACK_BACKGROUND("\u001B[40m"),
    ANSI_RED_BACKGROUND("\u001B[41m"),
    ANSI_GREEN_BACKGROUND("\u001B[42m"),
    ANSI_YELLOW_BACKGROUND("\u001B[43m"),
    ANSI_BLUE_BACKGROUND("\u001B[44m"),
    ANSI_PURPLE_BACKGROUND("\u001B[45m"),
    ANSI_CYAN_BACKGROUND("\u001B[46m"),
    ANSI_WHITE_BACKGROUND("\u001B[47m"),
    ANSI_BOLD("\033[0;1m"),
    ANSI_UNDERLINE("\033[4m"),
    DEFAULT_COLOR("");

    private String code;

    private AnsiColor(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
