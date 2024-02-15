package com.example.securitydemo.security.jwt;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import com.example.securitydemo.security.services.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class AuthTokenFilter extends OncePerRequestFilter{
	
	@Autowired
	private JwtUtils jwtUtils;
	
	@Autowired
	private UserDetailsServiceImpl userDetailsService;
	
	private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);
	
	/*
	 * Responsible for processing each HTTP request and providing authentication
	 * based on the presence and validity of a JWT token.
	 * This method intercepts incoming HTTP requests, extracts and validates JWT tokens, loads UserDetails, 
	 * creates an authentication token, sets it in the security context, and then 
	 * allows the request to proceed through the filter chain.
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse responce, FilterChain filterChain) 
			throws IOException, ServletException {
		try {
			//extracts the token from the request
			String jwt = parseJwt(request);
			//Checks if the JWT token exists and is valid
			if(jwt != null && jwtUtils.validateJwtToken(jwt)) {
				//Extracts the username from the JWT token
				String username = jwtUtils.getUsernameFromJwtToken(jwt);
				
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
						userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		} catch (Exception e) {
			logger.error("Cannot set user authentication: {}", e);
		}
		
		filterChain.doFilter(request, responce);
	}

	private String parseJwt(HttpServletRequest request) {
		String headerAuth = request.getHeader("Authorization");
		
		if(StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer "))
			return headerAuth.substring(7, headerAuth.length());
		
		return null;
	}
	
}
