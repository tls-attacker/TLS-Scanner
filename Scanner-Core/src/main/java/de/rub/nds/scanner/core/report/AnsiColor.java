/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.report;

import java.util.HashMap;
import java.util.Map;

public enum AnsiColor {
    RESET("\u001B[0m"),
    BLACK("\u001B[30m"),
    RED("\u001B[31m"),
    GREEN("\u001B[32m"),
    YELLOW("\u001B[33m"),
    BLUE("\u001B[34m"),
    PURPLE("\u001B[35m"),
    CYAN("\u001B[36m"),
    WHITE("\u001B[37m"),
    BLACK_BACKGROUND("\u001B[40m"),
    RED_BACKGROUND("\u001B[41m"),
    GREEN_BACKGROUND("\u001B[42m"),
    YELLOW_BACKGROUND("\u001B[43m"),
    BLUE_BACKGROUND("\u001B[44m"),
    PURPLE_BACKGROUND("\u001B[45m"),
    CYAN_BACKGROUND("\u001B[46m"),
    WHITE_BACKGROUND("\u001B[47m"),
    BOLD("\033[0;1m"),
    UNDERLINE("\033[4m"),
    DEFAULT_COLOR("");

    private String code;

    private static final Map<String, AnsiColor> MAP;

    private AnsiColor(String code) {
        this.code = code;
    }

    static {
        MAP = new HashMap<>();
        for (AnsiColor c : AnsiColor.values()) {
            MAP.put(c.code, c);
        }
    }

    public static AnsiColor getAnsiColor(String code) {
        return MAP.get(code);
    }

    public String getCode() {
        return code;
    }
}
