package com.example.SpringSecurity.config;

import com.example.SpringSecurity.service.JWTService;
import com.example.SpringSecurity.service.MyUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
//Make the filter sequence before executing the one filter
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;
    @Autowired
    ApplicationContext context;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    //Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwcmF2ZWVuIiwiaWF0IjoxNzM2NzY5MTUwLCJleHAiOjE3MzY3NjkyNTh9.aZ7ILlkg9bDsMQIROetDRIPmjT_ryleae_zgW8zVZtw
    String authHeader = request.getHeader("Authorization");
    String token=null;
    String username=null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            username=jwtService.extractUserName(token);

        }
        if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null) {

            UserDetails userDetails=context.getBean(MyUserDetailsService.class).loadUserByUsername(username);
            if(jwtService.validateToken(token,userDetails))
            {
                UsernamePasswordAuthenticationToken authtoken=
                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                authtoken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authtoken);

            }
        }
        filterChain.doFilter(request, response);

    }
}
