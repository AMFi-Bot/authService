package org.amfibot.auth.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper
import org.springframework.security.web.SecurityFilterChain


@Configuration
@EnableWebSecurity
class DefaultSecurityConfig {
    @Bean
    fun defaultSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.invoke {
            authorizeRequests {
                authorize("/.~~spring-boot!~/**", permitAll)
                authorize("/error", permitAll)
                authorize(anyRequest, authenticated)
            }

            oauth2Login {
                redirectionEndpoint {
                    baseUri = "/oauth2/callback/*"
                }
                userInfoEndpoint {
                    userAuthoritiesMapper = userAuthoritiesMapper()
                }
            }
        }


        return http.build()
    }


    /**
     *
     * Adds client to user authorities
     *
     * TODO: Remove this method when find solution for mapping user authorities on exchange user info step
     *
     */
    private fun userAuthoritiesMapper(): GrantedAuthoritiesMapper =
        GrantedAuthoritiesMapper { authorities: Collection<GrantedAuthority> ->
            val mappedAuthorities = authorities.toMutableList()

            // Adds OAUTH2_CLIENT_DISCORD to all users logged in through OAuth2
            // Here is only one client, so it is allowed
            mappedAuthorities.add(GrantedAuthority { "OAUTH2_CLIENT_DISCORD" })

            mappedAuthorities
        }
}