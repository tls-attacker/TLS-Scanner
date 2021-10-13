/**
 * Scanner-Core - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.scanner.core.report.container;

import de.rub.nds.scanner.core.constants.ScannerDetail;
import de.rub.nds.scanner.core.report.AnsiColor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyValueContainer extends ReportContainer {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int PADDED_KEY_LENGTH = 30;

    private String key;
    private AnsiColor keyColor;

    private String value;
    private AnsiColor valueColor;

    public KeyValueContainer(String key, AnsiColor keyColor, String value, AnsiColor valueColor) {
        super(ScannerDetail.NORMAL);
        this.key = key;
        this.keyColor = keyColor;
        this.value = value;
        this.valueColor = valueColor;
    }

    @Override
    public void print(StringBuilder builder, int depth, boolean useColor) {
        addDepth(builder, depth);
        addColor(builder, keyColor, pad(key, PADDED_KEY_LENGTH), useColor);
        builder.append(":    ");
        addColor(builder, valueColor, value, useColor);
        builder.append("\n");
    }

    private String pad(String text, int size) {
        if (text.length() < size) {
            StringBuilder builder = new StringBuilder(text);
            for (int i = 0; i < size - text.length(); i++) {
                builder.append(" ");
            }
            return builder.toString();
        } else if (text.length() > size) {
            LOGGER.warn("KeyValue 'Key' size is bigger than PADDED_KEY_LENGTH:" + PADDED_KEY_LENGTH
                + " - which breaks the layout. Consider choosing a shorter name or raising PADDED_KEY_LEGNTH");
            return text;
        } else {
            return text;
        }
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public AnsiColor getKeyColor() {
        return keyColor;
    }

    public void setKeyColor(AnsiColor keyColor) {
        this.keyColor = keyColor;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public AnsiColor getValueColor() {
        return valueColor;
    }

    public void setValueColor(AnsiColor valueColor) {
        this.valueColor = valueColor;
    }
}
