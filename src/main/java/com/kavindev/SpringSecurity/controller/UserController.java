package com.kavindev.SpringSecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.web.bind.annotation.*;

import javax.sql.DataSource;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    DataSource dataSource;

    @PostMapping("/users")
    public String createUser(@RequestParam String username,
                             @RequestParam String password,
                             @RequestParam String role){
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        if(userDetailsManager.userExists(username)){
            return "User already exist!!!";
        }
        UserDetails userDetails = User.withUsername(username)
                .password(encoder.encode(password))
                .roles(role)
                .build();
        userDetailsManager.createUser(userDetails);
        return "User created successfully!!!";
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        Map<String,Object> profile = new HashMap<>();
        profile.put("username",userDetails.getUsername());
        profile.put("roles",userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList()));
        profile.put("message","This is a user-specific content from backend");
        return ResponseEntity.ok(profile);
    }


}
