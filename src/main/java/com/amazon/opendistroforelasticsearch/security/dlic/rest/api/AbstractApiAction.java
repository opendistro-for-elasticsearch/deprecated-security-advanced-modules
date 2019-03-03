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

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.Settings.Builder;
import org.elasticsearch.common.util.concurrent.ThreadContext.StoredContext;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;
import org.elasticsearch.common.xcontent.XContentHelper;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.rest.BaseRestHandler;
import org.elasticsearch.rest.BytesRestResponse;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.threadpool.ThreadPool;

import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateAction;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateNodeResponse;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateRequest;
import com.amazon.opendistroforelasticsearch.security.action.configupdate.ConfigUpdateResponse;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator.ErrorType;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.user.User;

public abstract class AbstractApiAction extends BaseRestHandler {

	protected final Logger log = LogManager.getLogger(this.getClass());

	protected final IndexBaseConfigurationRepository cl;
	protected final ClusterService cs;
	final ThreadPool threadPool;
	private String opendistrosecurityIndex;
	private final RestApiPrivilegesEvaluator restApiPrivilegesEvaluator;
	protected final AuditLog auditLog;

	protected AbstractApiAction(final Settings settings, final Path configPath, final RestController controller,
			final Client client, final AdminDNs adminDNs, final IndexBaseConfigurationRepository cl,
			final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator,
			ThreadPool threadPool, AuditLog auditLog) {
		super(settings);
		this.opendistrosecurityIndex = settings.get(ConfigConstants.OPENDISTRO_SECURITY_CONFIG_INDEX_NAME,
				ConfigConstants.OPENDISTRO_SECURITY_DEFAULT_CONFIG_INDEX);

		this.cl = cl;
		this.cs = cs;
		this.threadPool = threadPool;
		this.restApiPrivilegesEvaluator = new RestApiPrivilegesEvaluator(settings, adminDNs, evaluator,
				principalExtractor, configPath, threadPool);
		this.auditLog = auditLog;
	}

	protected abstract AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params);

	protected abstract String getResourceName();

	protected abstract String getConfigName();

	protected Tuple<String[], RestResponse> handleApiRequest(final RestRequest request, final Client client)
			throws Throwable {

		// validate additional settings, if any
		AbstractConfigurationValidator validator = getValidator(request, request.content());
		if (!validator.validateSettings()) {
			request.params().clear();
			return new Tuple<String[], RestResponse>(new String[0],
					new BytesRestResponse(RestStatus.BAD_REQUEST, validator.errorsAsXContent()));
		}
		switch (request.method()) {
		case DELETE:
			return handleDelete(request, client, validator.settingsBuilder());
		case POST:
			return handlePost(request, client, validator.settingsBuilder());
		case PUT:
			return handlePut(request, client, validator.settingsBuilder());
		case GET:
			return handleGet(request, client, validator.settingsBuilder());
		default:
			throw new IllegalArgumentException(request.method() + " not supported");
		}
	}

	protected Tuple<String[], RestResponse> handleDelete(final RestRequest request, final Client client,
			final Settings.Builder additionalSettingsBuilder) throws Throwable {
		final String name = request.param("name");

		if (name == null || name.length() == 0) {
			return badRequestResponse("No " + getResourceName() + " specified");
		}

		final Settings existingAsSettings = loadAsSettings(getConfigName(), false);

		if (isHidden(existingAsSettings, name)) {
            return notFound(getResourceName() + " " + name + " not found.");
		}

		if (isReadOnly(existingAsSettings, name)) {
			return forbidden("Resource '"+ name +"' is read-only.");
		}

		final Map<String, Object> config = Utils.convertJsonToxToStructuredMap(Settings.builder().put(existingAsSettings).build());

		boolean resourceExisted = config.containsKey(name);
		config.remove(name);
		if (resourceExisted) {
			save(client, request, getConfigName(), Utils.convertStructuredMapToBytes(config));
			return successResponse("'" + name + "' deleted.", getConfigName());
		} else {
			return notFound(getResourceName() + " " + name + " not found.");
		}
	}

	protected Tuple<String[], RestResponse> handlePut(final RestRequest request, final Client client,
			final Settings.Builder additionalSettingsBuilder) throws Throwable {

		final String name = request.param("name");

		if (name == null || name.length() == 0) {
			return badRequestResponse("No " + getResourceName() + " specified");
		}

		final Settings existingAsSettings = loadAsSettings(getConfigName(), false);

		if (isHidden(existingAsSettings, name)) {
            return forbidden("Resource '"+ name +"' is not available.");
		}

		if (isReadOnly(existingAsSettings, name)) {
			return forbidden("Resource '"+ name +"' is read-only.");
		}

		if (log.isTraceEnabled()) {
			log.trace(additionalSettingsBuilder.build());
		}

		final Map<String, Object> con = Utils.convertJsonToxToStructuredMap(existingAsSettings);

		boolean existed = con.containsKey(name);

		con.put(name, Utils.convertJsonToxToStructuredMap(additionalSettingsBuilder.build()));

		save(client, request, getConfigName(), Utils.convertStructuredMapToBytes(con));
		if (existed) {
			return successResponse("'" + name + "' updated.", getConfigName());
		} else {
			return createdResponse("'" + name + "' created.", getConfigName());
		}
	}

	protected Tuple<String[], RestResponse> handlePost(final RestRequest request, final Client client,
			final Settings.Builder additionalSettings) throws Throwable {
		return notImplemented(Method.POST);
	}

	protected Tuple<String[], RestResponse> handleGet(RestRequest request, Client client, Builder additionalSettings)
			throws Throwable {

		final String resourcename = request.param("name");

		final Settings.Builder settingsBuilder = load(getConfigName(), true);

		// filter hidden resources and sensitive settings
		filter(settingsBuilder);

		final Settings configurationSettings = settingsBuilder.build();

		// no specific resource requested, return complete config
		if (resourcename == null || resourcename.length() == 0) {
			return new Tuple<String[], RestResponse>(new String[0],
					new BytesRestResponse(RestStatus.OK, convertToJson(configurationSettings)));
		}



		final Map<String, Object> con =
		        new HashMap<>(Utils.convertJsonToxToStructuredMap(Settings.builder().put(configurationSettings).build()))
		        .entrySet()
		        .stream()
		        .filter(f->f.getKey() != null && f.getKey().equals(resourcename)) //copy keys
		        .collect(Collectors.toMap(p -> p.getKey(), p -> p.getValue()));

		if (!con.containsKey(resourcename)) {
			return notFound("Resource '" + resourcename + "' not found.");
		}
		return new Tuple<String[], RestResponse>(new String[0],
				new BytesRestResponse(RestStatus.OK, XContentHelper.convertToJson(Utils.convertStructuredMapToBytes(con), false, false, XContentType.JSON)));
	}

	protected final Settings.Builder load(final String config, boolean triggerComplianceWhenCached) {
		return Settings.builder().put(loadAsSettings(config, triggerComplianceWhenCached));
	}

	protected final Settings loadAsSettings(final String config, boolean triggerComplianceWhenCached) {
		return cl.getConfiguration(config, triggerComplianceWhenCached);
	}

	protected boolean ensureIndexExists(final Client client) {
		if (!cs.state().metaData().hasConcreteIndex(this.opendistrosecurityIndex)) {
			return false;
		}
		return true;
	}

	protected void filter(Settings.Builder builder) {
	    Settings settings = builder.build();

        for (Map.Entry<String, Settings> entry : settings.getAsGroups(true).entrySet()) {
            if (entry.getValue().getAsBoolean("hidden", false)) {
                for (String subKey : entry.getValue().keySet()) {
                    builder.remove(entry.getKey() + "." + subKey);
                }
            }
        }
	}

	protected void save(final Client client, final RestRequest request, final String config,
            final Settings.Builder settings) throws Throwable {
	    save(client, request, config, toSource(settings));
	}

	protected void save(final Client client, final RestRequest request, final String config,
			final BytesReference bytesRef) throws Throwable {
		final Semaphore sem = new Semaphore(0);
		final List<Throwable> exception = new ArrayList<Throwable>(1);
		final IndexRequest ir = new IndexRequest(this.opendistrosecurityIndex);

		String type = "security";
		String id = config;

		if (cs.state().metaData().index(this.opendistrosecurityIndex).mapping("config") != null) {
			type = config;
			id = "0";
		}

		client.index(ir.type(type).id(id).setRefreshPolicy(RefreshPolicy.IMMEDIATE).source(config, bytesRef),
				new ActionListener<IndexResponse>() {

					@Override
					public void onResponse(final IndexResponse response) {
						sem.release();
						if (logger.isDebugEnabled()) {
							logger.debug("{} successfully updated", config);
						}
					}

					@Override
					public void onFailure(final Exception e) {
						sem.release();
						exception.add(e);
						logger.error("Cannot update {} due to", config, e);
					}
				});

		if (!sem.tryAcquire(2, TimeUnit.MINUTES)) {
			// timeout
			logger.error("Cannot update {} due to timeout}", config);
			throw new ElasticsearchException("Timeout updating " + config);
		}

		if (exception.size() > 0) {
			throw exception.get(0);
		}

	}

	@Override
	protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {

		// consume all parameters first so we can return a correct HTTP status,
		// not 400
		consumeParameters(request);

		// TODO: - Initialize if non-existant
		// check if Security index has been initialized
		if (!ensureIndexExists(client)) {
			return channel -> channel.sendResponse(
					new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, ErrorType.OPENDISTRO_SECURITY_NOT_INITIALIZED.getMessage()));
		}

		// check if request is authorized
		String authError = restApiPrivilegesEvaluator.checkAccessPermissions(request, getEndpoint());

		if (authError != null) {
			logger.error("No permission to access REST API: " + authError);
			final User user = (User) threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
			auditLog.logMissingPrivileges(authError, user==null?null:user.getName(), request);
			// for rest request
			request.params().clear();
			final BytesRestResponse response = (BytesRestResponse)forbidden("No permission to access REST API: " + authError).v2();
			return channel -> channel.sendResponse(response);
		}

		final Semaphore sem = new Semaphore(0);
		final List<Throwable> exception = new ArrayList<Throwable>(1);
		final Tuple<String[], RestResponse> response;

		final Object originalUser = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_USER);
		final Object originalRemoteAddress = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS);
		final Object originalOrigin = threadPool.getThreadContext().getTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN);

		try (StoredContext ctx = threadPool.getThreadContext().stashContext()) {

			threadPool.getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
			threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_USER, originalUser);
			threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_REMOTE_ADDRESS, originalRemoteAddress);
			threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_ORIGIN, originalOrigin);

			response = handleApiRequest(request, client);

			// reload config
			if (response.v1().length > 0) {

				final ConfigUpdateRequest cur = new ConfigUpdateRequest(response.v1());
				// cur.putInContext(ConfigConstants.OPENDISTRO_SECURITY_USER,
				// new User((String)
				// request.getFromContext(ConfigConstants.OPENDISTRO_SECURITY_SSL_PRINCIPAL)));

				client.execute(ConfigUpdateAction.INSTANCE, cur, new ActionListener<ConfigUpdateResponse>() {

					@Override
					public void onFailure(final Exception e) {
						sem.release();
						logger.error("Cannot update {} due to", Arrays.toString(response.v1()), e);
						exception.add(e);
					}

					@Override
					public void onResponse(final ConfigUpdateResponse ur) {
						sem.release();
						if (!checkConfigUpdateResponse(ur)) {
							logger.error("Cannot update {}", Arrays.toString(response.v1()));
							exception.add(
									new ElasticsearchException("Unable to update " + Arrays.toString(response.v1())));
						} else if (logger.isDebugEnabled()) {
							logger.debug("Configs {} successfully updated", Arrays.toString(response.v1()));
						}
					}
				});

			} else {
				sem.release();
			}

		} catch (final Throwable e) {
			logger.error("Unexpected exception {}", e.toString(), e);
			request.params().clear();
			return channel -> channel
					.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.toString()));
		}

		try {
			if (!sem.tryAcquire(2, TimeUnit.MINUTES)) {
				// timeout
				logger.error("Cannot update {} due to timeout", Arrays.toString(response.v1()));
				throw new ElasticsearchException("Timeout updating " + Arrays.toString(response.v1()));
			}
		} catch (final InterruptedException e) {
			Thread.currentThread().interrupt();
		}

		if (exception.size() > 0) {
			request.params().clear();
			return channel -> channel
					.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, exception.get(0).toString()));
		}

		return channel -> channel.sendResponse(response.v2());

	}

	protected static BytesReference toSource(final Settings.Builder settingsBuilder) throws IOException {
		final XContentBuilder builder = XContentFactory.jsonBuilder();
		builder.startObject(); // 1
		settingsBuilder.build().toXContent(builder, ToXContent.EMPTY_PARAMS);
		builder.endObject(); // 2
		return BytesReference.bytes(builder);
	}

	protected boolean checkConfigUpdateResponse(final ConfigUpdateResponse response) {

		final int nodeCount = cs.state().getNodes().getNodes().size();
		final int expectedConfigCount = 1;

		boolean success = response.getNodes().size() == nodeCount;
		if (!success) {
			logger.error(
					"Expected " + nodeCount + " nodes to return response, but got only " + response.getNodes().size());
		}

		for (final String nodeId : response.getNodesMap().keySet()) {
			final ConfigUpdateNodeResponse node = response.getNodesMap().get(nodeId);
			final boolean successNode = node.getUpdatedConfigTypes() != null
					&& node.getUpdatedConfigTypes().length == expectedConfigCount;

			if (!successNode) {
				logger.error("Expected " + expectedConfigCount + " config types for node " + nodeId + " but got only "
						+ Arrays.toString(node.getUpdatedConfigTypes()));
			}

			success = success && successNode;
		}

		return success;
	}

	protected static XContentBuilder convertToJson(Settings settings) throws IOException {
		XContentBuilder builder = XContentFactory.jsonBuilder();
		builder.prettyPrint();
		builder.startObject();
		settings.toXContent(builder, ToXContent.EMPTY_PARAMS);
		builder.endObject();
		return builder;
	}

	protected Tuple<String[], RestResponse> response(RestStatus status, String statusString, String message,
			String... configs) {

		try {
			final XContentBuilder builder = XContentFactory.jsonBuilder();
			builder.startObject();
			builder.field("status", statusString);
			builder.field("message", message);
			builder.endObject();
			String[] configsToUpdate = configs == null ? new String[0] : configs;
			return new Tuple<String[], RestResponse>(configsToUpdate, new BytesRestResponse(status, builder));
		} catch (IOException ex) {
			logger.error("Cannot build response", ex);
			return null;
		}
	}

	protected Tuple<String[], RestResponse> successResponse(String message, String... configs) {
		return response(RestStatus.OK, RestStatus.OK.name(), message, configs);
	}

	protected Tuple<String[], RestResponse> createdResponse(String message, String... configs) {
		return response(RestStatus.CREATED, RestStatus.CREATED.name(), message, configs);
	}

	protected Tuple<String[], RestResponse> badRequestResponse(String message) {
		return response(RestStatus.BAD_REQUEST, RestStatus.BAD_REQUEST.name(), message);
	}

	protected Tuple<String[], RestResponse> notFound(String message) {
		return response(RestStatus.NOT_FOUND, RestStatus.NOT_FOUND.name(), message);
	}

	protected Tuple<String[], RestResponse> forbidden(String message) {
		return response(RestStatus.FORBIDDEN, RestStatus.FORBIDDEN.name(), message);
	}

	protected Tuple<String[], RestResponse> internalErrorResponse(String message) {
		return response(RestStatus.INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR.name(), message);
	}

	protected Tuple<String[], RestResponse> unprocessable(String message) {
		return response(RestStatus.UNPROCESSABLE_ENTITY, RestStatus.UNPROCESSABLE_ENTITY.name(), message);
	}

	protected Tuple<String[], RestResponse> notImplemented(Method method) {
		return response(RestStatus.NOT_IMPLEMENTED, RestStatus.NOT_IMPLEMENTED.name(),
				"Method " + method.name() + " not supported for this action.");
	}

	protected boolean isReadOnly(Settings settings, String resourceName) {
	    return settings.getAsBoolean(resourceName+ "." + ConfigConstants.CONFIGKEY_READONLY, Boolean.FALSE);
	}

    protected boolean isHidden(Settings settings, String resourceName) {
        return settings.getAsBoolean(resourceName+ "." + ConfigConstants.CONFIGKEY_HIDDEN, Boolean.FALSE);
    }

	/**
	 * Consume all defined parameters for the request. Before we handle the
	 * request in subclasses where we actually need the parameter, some global
	 * checks are performed, e.g. check whether the Security index exists. Thus, the
	 * parameter(s) have not been consumed, and ES will always return a 400 with
	 * an internal error message.
	 *
	 * @param request
	 */
	protected void consumeParameters(final RestRequest request) {
		request.param("name");
	}

	@Override
	public String getName() {
		return getClass().getSimpleName();
	}

	protected abstract Endpoint getEndpoint();

}
