package org.amfibot.auth.config

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.amfibot.auth.jose.Jwks.generateRsa
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService
import org.springframework.security.oauth2.core.*
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.web.SecurityFilterChain
import java.time.Duration
import java.util.*


@Configuration(proxyBeanMethods = false)
class AuthorizationServerConfig {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)

        http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
            .oidc {} // Enable OpenID Connect 1.0

        // Accept access tokens for User Info and/or Client Registration
        http.invoke {
            oauth2ResourceServer {
                jwt { }
            }
        }

        return http.build()
    }

    /**
     *
     * Customizes tokens produced by authorization server
     *
     * @param authorizedClientService A service of OAuth2 LOGIN clients
     *
     */
    @Bean
    fun tokenCustomizer(authorizedClientService: OAuth2AuthorizedClientService): OAuth2TokenCustomizer<JwtEncodingContext> =
        OAuth2TokenCustomizer { context ->
            if (context.tokenType == OAuth2TokenType.ACCESS_TOKEN) {
                val claims = context.claims

                val principal = context.getPrincipal<Authentication>()


                // Process user authorized with discord
                if (principal.authorities.any { it.authority == "OAUTH2_CLIENT_DISCORD" }) {
                    claims.claim("userType", "discord")


                    val authorizedClient =
                        authorizedClientService.loadAuthorizedClient<OAuth2AuthorizedClient>(
                            "discord",
                            principal.name
                        )

                    val discordAccessToken = authorizedClient.accessToken

                    // Add discord user access token as claim
                    // Needed for clients to make api calls directly to discord
                    // for example, /users/@me, /users/@me/guilds, etc.
                    claims.claim("discordAccessToken", discordAccessToken.tokenValue)
                }
            }
        }


    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {

        // Base frontend client for amfi bot
        // It is a public client, so
        // No client_secret. Proof Key for Code Exchange (PKCE) required
        val frontendClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("amfiFrontend")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .clientSettings(ClientSettings.builder().requireProofKey(true).build())
            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofDays(1)).build())
            .scope(OidcScopes.OPENID)
            .redirectUri("http://localhost:3000/login_callback")
	    .redirectUri("http://localhost/login_callback")
            .build()
        return InMemoryRegisteredClientRepository(frontendClient)
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val rsaKey = generateRsa()
        val jwkSet = JWKSet(rsaKey)
        return JWKSource { jwkSelector: JWKSelector, _ -> jwkSelector.select(jwkSet) }
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>?): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder().build()
    }
}
