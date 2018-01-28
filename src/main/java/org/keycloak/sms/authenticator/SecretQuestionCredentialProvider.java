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

import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.OnUserCache;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.jboss.logging.Logger;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class SecretQuestionCredentialProvider implements CredentialProvider, CredentialInputValidator, CredentialInputUpdater, OnUserCache {

    public static final String SECRET_QUESTION = "SECRET_QUESTION";
    public static final String CACHE_KEY = SecretQuestionCredentialProvider.class.getName() + "." + SECRET_QUESTION;
    private final Logger log = Logger.getLogger(getClass().getName());

    protected KeycloakSession session;

    public SecretQuestionCredentialProvider(KeycloakSession session) {
        log.info("SecretQuestionCredentialProvider => " + session);
        this.session = session;
    }

    public CredentialModel getSecret(RealmModel realm, UserModel user) {
        log.info("getSecret => \nrealm => " + realm + "\nuser => " + user);
        CredentialModel secret = null;
        if (user instanceof CachedUserModel) {
            log.info("Cashed");
            CachedUserModel cached = (CachedUserModel) user;
            log.info("cached id => " + cached.getId() + " username => " + cached.getUsername());
            try {
                secret = (CredentialModel) cached.getCachedWith().get(CACHE_KEY);
            } catch (Exception e) {
                log.info("Error => " + e.getMessage());
            }

        } else {
            log.info("No Cashed");
            List<CredentialModel> creds = session.userCredentialManager().getStoredCredentialsByType(realm, user, SECRET_QUESTION);
            if (!creds.isEmpty()) {
                secret = creds.get(0);
            }
        }
        return secret;
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        log.info("updateCredential => " + realm + " user => " + user + " input=> " + input);
        if (!SECRET_QUESTION.equals(input.getType())) {
            return false;
        }
        if (!(input instanceof UserCredentialModel)) {
            return false;
        }
        UserCredentialModel credInput = (UserCredentialModel) input;
        List<CredentialModel> creds = session.userCredentialManager().getStoredCredentialsByType(realm, user, SECRET_QUESTION);
        if (creds.isEmpty()) {
            CredentialModel secret = new CredentialModel();
            secret.setType(SECRET_QUESTION);
            secret.setValue(credInput.getValue());
            secret.setCreatedDate(Time.currentTimeMillis());
            session.userCredentialManager().createCredential(realm, user, secret);
        } else {
            creds.get(0).setValue(credInput.getValue());
            session.userCredentialManager().updateCredential(realm, user, creds.get(0));
        }
        session.userCache().evict(realm, user);
        return true;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        log.info("disableCredentialType => " + realm + " user=> " + user + " credentialType => " + credentialType);
        if (!SECRET_QUESTION.equals(credentialType)) {
            return;
        }
        session.userCredentialManager().disableCredentialType(realm, user, credentialType);
        session.userCache().evict(realm, user);

    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        log.info("getDisableableCredentialTypes => " + realm + " user => " + user);
        if (!session.userCredentialManager().getStoredCredentialsByType(realm, user, SECRET_QUESTION).isEmpty()) {
            Set<String> set = new HashSet<>();
            set.add(SECRET_QUESTION);
            return set;
        } else {
            return Collections.EMPTY_SET;
        }

    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        log.info("supportsCredentialType => " + credentialType);
        return SECRET_QUESTION.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        log.info("isConfiguredFor => " + realm + " user => " + user + " credentialType => " + credentialType);
        if (!SECRET_QUESTION.equals(credentialType)) {
            return false;
        }
        return getSecret(realm, user) != null;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        log.info("isValid => " + realm + "\n\tuser => " + user + "\n\tinput => " + input);
        log.info("\tSECRET_QUESTION => " + SECRET_QUESTION);
        log.info("\tinput.getType() => " + input.getType());
        if (!SECRET_QUESTION.equals(input.getType())) {
            log.info(1);
            return false;
        }
        if (!(input instanceof UserCredentialModel)) {
            log.info(2);
            return false;
        }

        String secret = getSecret(realm, user).getValue();
        
        log.info("\tsecret => " + secret);

        return secret != null && ((UserCredentialModel) input).getValue().equals(secret);
    }

    @Override
    public void onCache(RealmModel realm, CachedUserModel user, UserModel delegate) {
        log.info("\n\tonCache => " + realm + " user => " + realm + " user => " + user + " delegate => " + delegate);
        List<CredentialModel> creds = session.userCredentialManager().getStoredCredentialsByType(realm, user, SECRET_QUESTION);
        if (!creds.isEmpty()) {
            log.info("cred => " + creds.get(0));
            user.getCachedWith().put(CACHE_KEY, creds.get(0));
            log.info("GOOD");
        }
    }
}
