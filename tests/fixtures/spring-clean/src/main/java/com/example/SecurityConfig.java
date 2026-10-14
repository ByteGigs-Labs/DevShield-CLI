package com.example;

public class SecurityConfig {
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a
            .requestMatchers("/health").permitAll()
            .anyRequest().authenticated());
        return http.build();
    }
}
