package com.api.configserver.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.server.SecurityWebFilterChain
import reactor.core.publisher.Mono


@Configuration
@EnableWebFluxSecurity
class SecurityConfig {

    @Bean
    fun bCryptPasswordEncoder(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder()
    }
    @Bean
    fun securityWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        http.csrf { csrf -> csrf.disable() }
            .authorizeExchange { authorize ->
                authorize.anyExchange().authenticated()
            }
            .httpBasic(Customizer.withDefaults())

        return http.build()
    }
    @Bean
    fun userDetailsService(): ReactiveUserDetailsService {
        val user: UserDetails = User.withUsername("admin")
            .password(bCryptPasswordEncoder().encode("password"))
            .roles("ADMIN")
            .build()


        val userDetailsService = MapReactiveUserDetailsService(user)

        userDetailsService.findByUsername("admin")
            .doOnNext { println("User found: $it") }
            .doOnError { println("Error finding user: ${it.message}") }
            .subscribe()

        return userDetailsService
    }


}