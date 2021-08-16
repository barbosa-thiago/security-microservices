package com.thiago.valhallaproject.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.thiago.valhallaproject.domain.ApplicationUser;
import com.thiago.valhallaproject.property.JwtConfiguration;
import com.thiago.valhallaproject.security.token.creator.TokenCreator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class JwtUserNamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtConfiguration jwtConfiguration;
    private final TokenCreator tokenCreator;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        log.info("Attempting authentication...");
        try {
            ApplicationUser applicationUser = new ObjectMapper().readValue(request.getInputStream(), ApplicationUser.class);
            if (applicationUser == null)
                throw new UsernameNotFoundException("Username or password didn't match");
            log.info("Creating authentication objectfor the user {} and calling UserDetailsServiceImpl loadUserByUsername", applicationUser.getUsername());
            UsernamePasswordAuthenticationToken token =
                    new UsernamePasswordAuthenticationToken(applicationUser.getUsername(), applicationUser.getPassword());
            token.setDetails(applicationUser);
            return authenticationManager.authenticate(token);

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication auth) {

        log.info("The authentication was succesful");
        SignedJWT signedJwt = tokenCreator.createSignedJwt(auth);
        String encriptedToken = tokenCreator.encriptToken(signedJwt);
        log.info("Token generated succesfully, adding it to the response header");

        response.addHeader("Access-Control-Expose-Header", "XSRF-TOKEN, " + jwtConfiguration.getHeader().getName());
        response.addHeader(jwtConfiguration.getHeader().getName(), jwtConfiguration.getHeader().getPrefix() + encriptedToken);

    }

}

