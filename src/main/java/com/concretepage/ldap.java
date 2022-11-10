package com.concretepage;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.ldap.core.ContextSource;

public class ldap {

  @Autowired
  private ContextSource contextSource;

  @Autowired
  private Environment env;

  public void authenticate(String username, String password) {
    contextSource.getContext(
      "cn=" +
      username +
      ",ou=users," +
      env.getRequiredProperty("ldap.partitionSuffix"),
      password
    );
  }
}
