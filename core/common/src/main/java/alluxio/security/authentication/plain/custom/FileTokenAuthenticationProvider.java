/*
 * The Alluxio Open Foundation licenses this work under the Apache License, version 2.0
 * (the "License"). You may not use this work except in compliance with the License, which is
 * available at www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied, as more fully set forth in the License.
 *
 * See the NOTICE file distributed with this work for information regarding copyright ownership.
 */

package alluxio.security.authentication.plain.custom;

import alluxio.conf.Configuration;
import alluxio.conf.PropertyKey;
import alluxio.security.authentication.AuthenticationProvider;

import alluxio.util.Sm4Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.sasl.AuthenticationException;

/**
 * {@link FileTokenAuthenticationProvider} implementation for Custom schemes.
 */
public class FileTokenAuthenticationProvider implements AuthenticationProvider {
  private static final Logger LOG = LoggerFactory.getLogger(
      FileTokenAuthenticationProvider.class);

  /**
   * Constructs a new {@link FileTokenAuthenticationProvider}.
   */
  public FileTokenAuthenticationProvider() {
  }

  @Override
  public void authenticate(String user, String password) throws AuthenticationException {
    LOG.debug("TOKEN: user=" + user + ",token=" + password);
    if (password == null || password.isEmpty()) {
      throw new AuthenticationException("User password must not be null or empty for CUSTOM "
          + "FileToken authentication.");
    }

    String verifyToken = getUserTokenFromConf(user);
    if (!password.equals(verifyToken)) {
      throw new AuthenticationException("User name or password verification failed.");
    }
  }

  private String getUserTokenFromConf(String username) {
    PropertyKey userKey = PropertyKey.Template.SECURITY_USER_LOGIN_TOKEN.format(username);
    String secretKey = Configuration.getString(PropertyKey.SECURITY_TOKEN_SECRET_KEY);
    if (Configuration.isSet(userKey)) {
      return new Sm4Utils(secretKey).decrypt(Configuration.getString(userKey));
    }
    return "defaultPassword";
  }
}

