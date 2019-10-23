/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.ssl.util.SSLConfigConstants;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import com.amazon.opendistroforelasticsearch.security.test.SingleClusterTest;
import com.amazon.opendistroforelasticsearch.security.test.helper.file.FileHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.Assert;
import org.junit.Test;

import java.io.File;
import java.io.StringWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

public class MigrationTests extends SingleClusterTest {

    @Test
    public void testSecurityMigrate() throws Exception {

        URL fileUrl = FileHelper.class.getClassLoader().getResource("node-0-keystore.jks");
        URL trust = FileHelper.class.getClassLoader().getResource("truststore.jks");
        File node = File.createTempFile("node", ".jks");
        File trustF = File.createTempFile("trust", ".jks");
        node.deleteOnExit();
        trustF.deleteOnExit();
        FileUtils.copyInputStreamToFile(fileUrl.openStream(), node);
        FileUtils.copyInputStreamToFile(trust.openStream(), trustF);
        StringWriter sw = new StringWriter();
        IOUtils.copy(FileHelper.class.getResourceAsStream('/' + "node-0-keystore.jks"), sw, StandardCharsets.UTF_8);
        String out = sw.toString();
//        System.out.println(out);
//        System.out.println(node.getAbsolutePath());

        System.out.println(FileHelper.getAbsoluteFilePathFromClassPath("migration/node-0-keystore.jks"));
        System.out.println(FileHelper.getAbsoluteFilePathFromClassPath("migration/truststore.jks"));
        File file = null;
        Path path = null;
        if (fileUrl != null) {
            file = new File(fileUrl.toExternalForm());



            System.out.println(fileUrl.toExternalForm());
//            System.out.println(file.getAbsolutePath());
//            path = Paths.get(file.getAbsolutePath());
//            System.out.println("path: ");
//            System.out.println(path);


            if(!file.exists()){
                System.out.println("does not exist");
            }
            if(!file.canRead()){
                System.out.println("cannot read");
            }
            if (file.exists() && file.canRead()) {
                System.out.println("can read");
            }
        }

        final Settings settings = Settings.builder().put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
                .put("opendistro_security.ssl.http.enabled", true)
                .put("opendistro_security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("migration/node-0-keystore.jks"))
                .put("opendistro_security.ssl.http.truststore_filepath",FileHelper.getAbsoluteFilePathFromClassPath("migration/truststore.jks")).build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        HttpResponse res = rh.executePostRequest("_opendistro/_security/api/migrate?pretty", "");
        assertContains(res, "*Migration completed*");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executePostRequest("_opendistro/_security/api/migrate?pretty", "");
        assertContains(res, "*it was already migrated*");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, res.getStatusCode());

        res = rh.executeGetRequest("_opendistro/_security/api/validate?pretty");
        assertContains(res, "*it was already migrated*");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, res.getStatusCode());

    }

    @Test
    public void testSecurityMigrateInvalid() throws Exception {
        final Settings settings = Settings.builder().put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
                .put("searchguard.ssl.http.enabled", true)
                .put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, true)
                .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityInternalUsers("security_internal_users2.yml").setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        HttpResponse res = rh.executePostRequest("_searchguard/api/migrate?pretty", "");
        assertContains(res, "*Migration completed*");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executePostRequest("_searchguard/api/migrate?pretty", "");
        assertContains(res, "*it was already migrated*");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, res.getStatusCode());

        res = rh.executeGetRequest("_searchguard/api/validate?pretty");
        assertContains(res, "*it was already migrated*");
        Assert.assertEquals(HttpStatus.SC_BAD_REQUEST, res.getStatusCode());

    }

    @Test
    public void testSecurityValidate() throws Exception {
        final Settings settings = Settings.builder().put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
                .put("opendistro_security.ssl.http.enabled", true)
                .put("opendistro_security.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("opendistro_security.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks")).build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        HttpResponse res = rh.executeGetRequest("_opendistro/_security/api/validate?pretty");
        assertContains(res, "*OK*");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

    }

    @Test
    public void testSgValidateWithInvalidConfig() throws Exception {
        final Settings settings = Settings.builder().put(SSLConfigConstants.OPENDISTRO_SECURITY_SSL_HTTP_CLIENTAUTH_MODE, "REQUIRE")
                .put("searchguard.ssl.http.enabled", true)
                .put("searchguard.ssl.http.keystore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.http.truststore_filepath", FileHelper.getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put(ConfigConstants.OPENDISTRO_SECURITY_UNSUPPORTED_ACCEPT_INVALID_CONFIG, true)
                .build();
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityInternalUsers("security_internal_users2.yml").setLegacy(), settings, true);
        final RestHelper rh = restHelper(); //ssl resthelper

        rh.enableHTTPClientSSL = true;
        rh.trustHTTPServerCertificate = true;
        rh.sendHTTPClientCertificate = true;
        rh.keystore = "kirk-keystore.jks";

        HttpResponse res = rh.executeGetRequest("_searchguard/api/validate?accept_invalid=true&pretty");
        assertContains(res, "*OK*");
        Assert.assertEquals(HttpStatus.SC_OK, res.getStatusCode());

        res = rh.executeGetRequest("_searchguard/api/validate?pretty");
        assertContains(res, "*Configuration is not valid*");
        Assert.assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, res.getStatusCode());

    }

    @Override
    protected String getType() {
        return "security";
    }

    @Override
    protected String getResourceFolder() {
        return "migration";
    }
}
