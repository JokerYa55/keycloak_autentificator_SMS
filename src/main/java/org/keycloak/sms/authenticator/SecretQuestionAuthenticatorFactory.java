/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.sms.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;
import org.jboss.logging.Logger;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class SecretQuestionAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "secret-question-authenticator";
    private static final SecretQuestionAuthenticator SINGLETON = new SecretQuestionAuthenticator();
    private final Logger log = Logger.getLogger(getClass().getName());

    @Override
    public String getId() {
        log.info("getId");
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        log.info("create => " + session);
        return SINGLETON;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED
    };
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        log.info("getRequirementChoices()");
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        log.info("isUserSetupAllowed()");
        return true;
    }

    @Override
    public boolean isConfigurable() {
        log.info("isConfigurable()");
        return true;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        log.info("getConfigProperties()");
        return configProperties;
    }

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("cookie.max.age");
        property.setLabel("Cookie Max Age");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Max age in seconds of the SECRET_QUESTION_COOKIE.");
        configProperties.add(property);
    }


    @Override
    public String getHelpText() {
        log.info("getHelpText()");
        return "A secret question that a user has to answer. i.e. What is your mother's maiden name.";
    }

    @Override
    public String getDisplayType() {
        log.info("getDisplayType()");
        return "Secret Question";
    }

    @Override
    public String getReferenceCategory() {
        log.info("getReferenceCategory()");
        return "Secret Question";
    }

    @Override
    public void init(Config.Scope config) {
        log.info("init => " + config);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        log.info("postInit => " + factory);
    }

    @Override
    public void close() {
        log.info("close()");
    }


}
