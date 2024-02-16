package com.example.securitydemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.example.securitydemo.security.jwt.AuthEntryPointJwt;
import com.example.securitydemo.security.jwt.AuthTokenFilter;
import com.example.securitydemo.security.services.UserDetailsServiceImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig {
	
	@Autowired
	UserDetailsServiceImpl userDetailsService;
	
	@Autowired
	private AuthEntryPointJwt unauthorizedHandler;
	
	
	//Bean Method that returns AuthTokenFilte object
	//AuthTokenFilter - Responsible for JWT token validation and setting up authentication based on the token
	@Bean 
	public AuthTokenFilter authenticationJwtTokenFilter() {
		return new AuthTokenFilter();
	}
	
	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		//implements the AuthenticationProvider interface. It's commonly used for authenticating users.
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder());
		
		return authProvider;
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		return authConfig.getAuthenticationManager();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
	    return new BCryptPasswordEncoder();
	}
	
	//Used to configure how incoming HTTP requests should be handled in terms of security
	//HttpSecurity - allows configuring web-based security for specific HTTP requests.
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		//Disables CSRF (Cross-Site Request Forgery) protection.
		//This is commonly done for stateless APIs secured with JWT tokens.
		http.csrf(csrf -> csrf.disable())
			// The unauthorizedHandler bean is likely responsible for handling unauthorized access attempts.
			.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
			// no session management will be done by Spring Security
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and())
			.authorizeHttpRequests(auth -> 
			auth.requestMatchers("/api/auth/**").permitAll()
				.requestMatchers("/api/test/**").permitAll()
				//Requires authentication for any other request
				.anyRequest().authenticated()
			);
		
		//This is where the application-specific authentication logic is configured
		http.authenticationProvider(authenticationProvider());
		
		//Adds a custom filter (authenticationJwtTokenFilter()) before the UsernamePasswordAuthenticationFilter
		//
		http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
		
		/*
		 * build - Finalization: It performs any finalization steps required before returning
		 * the configured HttpSecurity object. This might include setting default values
		 * for unspecified configurations or ensuring consistency in the configuration.
		 */
		return http.build();
	}
	
}
