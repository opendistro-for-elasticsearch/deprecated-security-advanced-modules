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

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateAction;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateRequest;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateResponse;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.NoOpValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;

public class FlushCacheApiAction extends AbstractApiAction {

	@Inject
	public FlushCacheApiAction(final Settings settings, final Path configPath, final RestController controller, final Client client,
			final AdminDNs adminDNs, final IndexBaseConfigurationRepository cl, final ClusterService cs,
            final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator, ThreadPool threadPool, AuditLog auditLog) {
		super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool, auditLog);
		controller.registerHandler(Method.DELETE, "/_opendistro/_security/api/cache", this);
		controller.registerHandler(Method.GET, "/_opendistro/_security/api/cache", this);
		controller.registerHandler(Method.PUT, "/_opendistro/_security/api/cache", this);
		controller.registerHandler(Method.POST, "/_opendistro/_security/api/cache", this);
	}

	@Override
	protected Endpoint getEndpoint() {
		return Endpoint.CACHE;
	}

	@Override
	protected Tuple<String[], RestResponse> handleDelete(RestRequest request, Client client, Builder additionalSettingsBuilder)
			throws Throwable {

		final Semaphore sem = new Semaphore(0);
		final List<Throwable> exception = new ArrayList<Throwable>(1);

		client.execute(
				ConfigUpdateAction.INSTANCE,
				new ConfigUpdateRequest(new String[] { "config", "roles", "rolesmapping", "internalusers", "actiongroups" }),
				new ActionListener<ConfigUpdateResponse>() {

					@Override
					public void onResponse(ConfigUpdateResponse response) {
						sem.release();
						if (logger.isDebugEnabled()) {
							logger.debug("cache flushed successfully");
						}
					}

					@Override
					public void onFailure(Exception e) {
						sem.release();
						exception.add(e);
						logger.error("Cannot flush cache due to {}", e.toString(), e);
					}

				}
		);

		if (!sem.tryAcquire(30, TimeUnit.SECONDS)) {
			logger.error("Cannot flush cache due to timeout");
			return internalErrorResponse("Cannot flush cache due to timeout");
		}

		if (exception.size() > 0) {
			logger.error("Cannot flush cache due to", exception.get(0));
			return internalErrorResponse("Cannot flush cache due to "+ exception.get(0).getMessage());
		}

		return successResponse("Cache flushed successfully.", new String[0]);
	}

	@Override
	protected Tuple<String[], RestResponse> handlePost(final RestRequest request, final Client client,
			final Settings.Builder additionalSettings) throws Throwable {
		return notImplemented(Method.POST);
	}

	@Override
	protected Tuple<String[], RestResponse> handleGet(final RestRequest request, final Client client,
			final Settings.Builder additionalSettings) throws Throwable {
		return notImplemented(Method.GET);
	}

	@Override
	protected Tuple<String[], RestResponse> handlePut(final RestRequest request, final Client client,
			final Settings.Builder additionalSettings) throws Throwable {
		return notImplemented(Method.PUT);
	}

	@Override
	protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... param) {
		return new NoOpValidator(request, ref, this.settings, param);
	}

	@Override
	protected String getResourceName() {
		// not needed
		return null;
	}

	@Override
	protected String getConfigName() {
		// not needed
		return null;
	}

	@Override
	protected void consumeParameters(final RestRequest request) {
		// not needed
	}

}
