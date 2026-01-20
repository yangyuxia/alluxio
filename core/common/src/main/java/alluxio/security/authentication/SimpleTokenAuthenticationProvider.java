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

package alluxio.security.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.sasl.AuthenticationException;

/**
 * {@link SimpleTokenAuthenticationProvider} implementation for Custom schemes.
 */
public class SimpleTokenAuthenticationProvider implements AuthenticationProvider {
  private static final Logger LOG = LoggerFactory.getLogger(
      SimpleTokenAuthenticationProvider.class);

  /**
   * Constructs a new {@link SimpleTokenAuthenticationProvider}.
  */
  public SimpleTokenAuthenticationProvider() {
  }

  @Override
  public void authenticate(String user, String password) throws AuthenticationException {
    LOG.info("TOKEN: user=" + user + ",password=" + password);
    if (password == null || password.isEmpty()) {
      throw new AuthenticationException("TOKEN: user password must be specified");
    }
  }
}

