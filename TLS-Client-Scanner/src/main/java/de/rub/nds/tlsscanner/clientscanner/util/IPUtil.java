package de.rub.nds.tlsscanner.clientscanner.util;

public class IPUtil {
    private IPUtil() {
        throw new UnsupportedOperationException("Utility class");
    }

    public static boolean validIP(String ip) {
        // https://stackoverflow.com/a/5240291/
        try {
            if (ip == null || ip.isEmpty()) {
                return false;
            }

            String[] parts = ip.split("\\.");
            if (parts.length != 4) {
                return false;
            }

            for (String s : parts) {
                int i = Integer.parseInt(s);
                if ((i < 0) || (i > 255)) {
                    return false;
                }
            }
            if (ip.endsWith(".")) {
                return false;
            }

            return true;
        } catch (NumberFormatException nfe) {
            return false;
        }
    }
}
