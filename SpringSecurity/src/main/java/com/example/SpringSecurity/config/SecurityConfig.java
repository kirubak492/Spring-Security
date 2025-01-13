package com.example.SpringSecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig { //used to build the manual configuration insted of default


    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtFilter jwtFilter;

    // how incoming requests should be authenticated and how sessions are managed, among other security aspects
   @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return  http
                 .csrf(customizer ->customizer.disable())
                 .authorizeHttpRequests(request -> request
                                .requestMatchers("register","login")
                                .permitAll()
                                .anyRequest().authenticated()) //make all request is authenticated and some is open

                .httpBasic(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    // Give Authentication for all users in database
    //By default it use some authentication provider
    // We need to configure the authentication for our database username and password
    @Bean
    public AuthenticationProvider authenticationProvider() {


       DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        // pass 2 parrametrs
      // provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance()); firstly configured then changed
        provider.setPasswordEncoder(new BCryptPasswordEncoder(12));// understand the db password as encrypted to normal
       provider.setUserDetailsService(userDetailsService); //we need to pass own user detail service
       return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
       return config.getAuthenticationManager();
    }




//   // User details to connnect with application
//    @Bean
//     public UserDetailsService userDetailsService() {
//       // these are the customized user to login the web applicatin
//        UserDetails user1 = User
//                .withDefaultPasswordEncoder()
//                .username("krishna")
//                .password(("1234"))
//                .roles("USER")
//                .build();
//
//        UserDetails user2 = User
//                .withDefaultPasswordEncoder()
//                .username("kiruba")
//                .password(("1234"))
//                .roles("ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(user1,user2);
//    }
}
