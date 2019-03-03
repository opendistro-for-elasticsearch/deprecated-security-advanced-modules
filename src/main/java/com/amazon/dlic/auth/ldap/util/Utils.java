/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.dlic.auth.ldap.util;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import org.apache.logging.log4j.LogManager;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.settings.Settings;
import org.ldaptive.Connection;

public final class Utils {

    private static final String RFC2254_ESCAPE_CHARS = "\\*()\000";

    private Utils() {

    }

    public static void init() {
        // empty init() to allow prior initialization
    }

    public static void unbindAndCloseSilently(final Connection connection) {
        if (connection == null) {
            return;
        }

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        try {
            AccessController.doPrivileged(new PrivilegedExceptionAction<Object>() {
                @Override
                public Object run() throws Exception {
                    connection.close();
                    return null;
                }
            });
        } catch (PrivilegedActionException e) {
            // ignore
        }
    }

    /**
     * RFC 2254 string escaping
     */
    public static String escapeStringRfc2254(final String str) {

        if (str == null || str.length() == 0) {
            return str;
        }

        final StringTokenizer tok = new StringTokenizer(str, RFC2254_ESCAPE_CHARS, true);

        if (tok.countTokens() == 0) {
            return str;
        }

        final StringBuilder out = new StringBuilder();
        while (tok.hasMoreTokens()) {
            final String s = tok.nextToken();

            if (s.equals("*")) {
                out.append("\\2a");
            } else if (s.equals("(")) {
                out.append("\\28");
            } else if (s.equals(")")) {
                out.append("\\29");
            } else if (s.equals("\\")) {
                out.append("\\5c");
            } else if (s.equals("\000")) {
                out.append("\\00");
            } else {
                out.append(s);
            }
        }
        return out.toString();
    }

    public static List<Map.Entry<String, Settings>> getOrderedBaseSettings(Settings settings) {
        return getOrderedBaseSettings(settings.getAsGroups(true));
    }

    public static List<Map.Entry<String, Settings>> getOrderedBaseSettings(Map<String, Settings> settingsMap) {
        return getOrderedBaseSettings(settingsMap.entrySet());
    }

    public static List<Map.Entry<String, Settings>> getOrderedBaseSettings(Set<Map.Entry<String, Settings>> set) {
        List<Map.Entry<String, Settings>> result = new ArrayList<>(set);

        sortBaseSettings(result);

        return Collections.unmodifiableList(result);
    }

    private static void sortBaseSettings(List<Map.Entry<String, Settings>> list) {
        list.sort(new Comparator<Map.Entry<String, Settings>>() {

            @Override
            public int compare(Map.Entry<String, Settings> o1, Map.Entry<String, Settings> o2) {
                int attributeOrder = Integer.compare(o1.getValue().getAsInt("order", Integer.MAX_VALUE),
                        o2.getValue().getAsInt("order", Integer.MAX_VALUE));

                if (attributeOrder != 0) {
                    return attributeOrder;
                }

                return o1.getKey().compareTo(o2.getKey());
            }
        });
    }

}
