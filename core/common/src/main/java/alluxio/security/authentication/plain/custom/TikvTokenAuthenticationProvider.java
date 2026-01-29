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
import org.tikv.common.TiConfiguration;
import org.tikv.common.TiSession;
import org.tikv.raw.RawKVClient;
import org.tikv.shade.com.google.protobuf.ByteString;

import java.util.Optional;
import javax.security.sasl.AuthenticationException;

/**
 * {@link TikvTokenAuthenticationProvider} implementation for Custom schemes.
 */
public class TikvTokenAuthenticationProvider implements AuthenticationProvider {
  private static final Logger LOG = LoggerFactory.getLogger(
      TikvTokenAuthenticationProvider.class);

  /**
   * Constructs a new {@link TikvTokenAuthenticationProvider}.
   */
  public TikvTokenAuthenticationProvider() {
  }

  @Override
  public void authenticate(String user, String password) throws AuthenticationException {
    LOG.debug("TOKEN: user=" + user + ",token=" + password);
    if (password == null || password.isEmpty()) {
      throw new AuthenticationException("User password must not be null or empty for CUSTOM "
          + "TikvToken authentication.");
    }

    String verifyToken = getUserTokenFromTikv(user);
    if (!password.equals(verifyToken)) {
      throw new AuthenticationException("User name or password verification failed.");
    }
  }

  private String getUserTokenFromTikv(String username) {
    String hostConf = Configuration.getString(PropertyKey.MASTER_METASTORE_INODE_TIKV_CONNECTION);
    String secretKey = Configuration.getString(PropertyKey.SECURITY_TOKEN_SECRET_KEY);

    TiConfiguration tikvConf = TiConfiguration.createDefault(hostConf);
    Optional<ByteString> token;
    try (TiSession tikvSession = TiSession.create(tikvConf)) {
      try (RawKVClient tikvClient = tikvSession.createRawClient()) {
        PropertyKey userKey = PropertyKey.Template.SECURITY_USER_LOGIN_TOKEN.format(username);
        token = tikvClient.get(ByteString.copyFromUtf8(userKey.getName()));
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    if (token != null && token.isPresent()) {
      return new Sm4Utils(secretKey).decrypt(token.get().toStringUtf8());
    }
    return "defaultPassword";
  }
}

