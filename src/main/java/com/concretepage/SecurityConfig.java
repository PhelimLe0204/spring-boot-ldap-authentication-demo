package com.concretepage;

import java.util.Hashtable;
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  @Value("${spring.ldap.server.url:#{null}}")
  private String ldapUrl;

  @Value("${spring.ldap.server.port:#{null}}")
  private String ldapPort;

  @Value("${spring.ldap.server.base:#{null}}")
  private String ldapBaseDn;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .authorizeRequests()
      .antMatchers("/secure/man/**")
      .access("hasRole('MANAGERS')")
      .antMatchers("/secure/dev/**")
      .access("hasRole('DEVELOPERS')")
      .and()
      .formLogin()
      .loginPage("/login")
      .loginProcessingUrl("/appLogin")
      .usernameParameter("username")
      .passwordParameter("password")
      .defaultSuccessUrl("/secure/dev")
      .and()
      .logout()
      .logoutUrl("/appLogout")
      .logoutSuccessUrl("/login")
      .and()
      .exceptionHandling()
      .accessDeniedPage("/accessDenied");
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    Hashtable<String, Object> env = new Hashtable<String, Object>();
    String principalName = "levanthanh@ansv.vn"; // Username
    String credentialsValue = "Thanh0204"; // Password
    env.put(
      Context.INITIAL_CONTEXT_FACTORY,
      "com.sun.jndi.ldap.LdapCtxFactory"
    );
    env.put(Context.PROVIDER_URL, ldapUrl + ldapPort + ldapBaseDn);
    env.put(Context.SECURITY_AUTHENTICATION, "simple");
    env.put(Context.SECURITY_PRINCIPAL, principalName);
    env.put(Context.SECURITY_CREDENTIALS, credentialsValue);

    try {
      DirContext authContext = new InitialDirContext(env);
      // User có trong server LDAP -> Authenticate success
      System.out.println("USER IS AUTHETICATED");
      // 1 - Kiểm tra user tòn tại trong DB
      // 2 - Nếu không tồn tại -> Insert tài khoản vào DB
      // 3 - Lưu
      auth
        .inMemoryAuthentication()
        .withUser(principalName)
        .password(passwordEncoder().encode(credentialsValue))
        .roles("MANAGERS");
      
        // auth.jdbcAuthentication().dataSource(dataSource)
        //        .usersByUsernameQuery("select username,password, enabled from users where username=?")
        //        .authoritiesByUsernameQuery("select username, role from user_roles where username=?");
    } catch (AuthenticationException ex) {
      // Authentication failed
      System.out.println("AUTH FAILED : " + ex);
    } catch (NamingException ex) {
      ex.printStackTrace();
    }
    // auth
    //   .ldapAuthentication()
    //   .userDnPatterns("uid={0},ou=people")
    //   .userSearchBase("ou=people")
    //   .userSearchFilter("uid={0}")
    //   .groupSearchBase("ou=groups")
    //   .groupSearchFilter("uniqueMember={0}")
    //   .contextSource()
    //   .url("ldap://localhost:2389/dc=concretepage,dc=com")
    //   .and()
    //   .passwordCompare()
    //   .passwordEncoder(passwordEncoder())
    //   .passwordAttribute("userPassword");
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    return passwordEncoder;
  }
}
