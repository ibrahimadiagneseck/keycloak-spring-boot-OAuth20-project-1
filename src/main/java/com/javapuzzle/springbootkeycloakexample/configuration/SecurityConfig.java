package com.javapuzzle.springbootkeycloakexample.configuration;

import javax.annotation.security.RolesAllowed;

import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;


@KeycloakConfiguration //Configuration spécifique à Keycloak
@Import(KeycloakSpringBootConfigResolver.class) //Importe la configuration de Keycloak pour Spring Boot
@EnableWebSecurity //Active la sécurisation des méthodes avec les annotations JSR-250 (par exemple, @RolesAllowed) : ajouter @RolesAllowed({"employee","admin"})
@EnableGlobalMethodSecurity(jsr250Enabled = true)
public class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {
	
	/**
	 * Enregistre KeycloakAuthenticationProvider auprès du gestionnaire d'authentification.
	 */
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
		// Utilise le mappage simple pour les rôles/autorisations
		keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
		auth.authenticationProvider(keycloakAuthenticationProvider);
	}

	/**
	 * Définit la stratégie d'authentification de session.
	 */
	@Bean
	@Override
	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
		// Utilise la stratégie d'authentification de session basée sur les registres
		return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
	}

	@Bean
	protected SessionRegistry buildSessionRegistry() {
		// Crée un registre de session pour stocker les informations sur les sessions actives
		return new SessionRegistryImpl();
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		// Expose l'instance d'AuthenticationManager pour être utilisée par d'autres composants
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception
	{
		super.configure(http);
		// Configure les règles d'autorisation pour les requêtes HTTP

		http
		.authorizeRequests()
		// Définit des règles d'autorisation basées sur les URL
		             // .antMatchers("/admin/*").hasRole("admin") // ajouter @RolesAllowed({"employee","admin"})
		             // .antMatchers("/user/*").hasRole("employee") // ajouter @RolesAllowed({"employee","admin"})
		.anyRequest().permitAll(); // Autorise toutes les autres requêtes sans authentification

		// Désactive la protection CSRF (Cross-Site Request Forgery)
		http.csrf().disable();
	}
}
