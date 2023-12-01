package googleauthenticator.configs.security

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import googleauthenticator.domain.CustomUserDetails
import googleauthenticator.domain.Permission
import googleauthenticator.service.AuthenticationStore
import org.apache.logging.log4j.LogManager
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.*
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.*
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.*
import java.util.stream.Collectors


@Configuration
@EnableWebSecurity
class SecurityConfig(private val configuration: AuthenticationConfiguration, private val authenticationStore: AuthenticationStore) {
    val log = LogManager.getLogger(javaClass)
    val WHITE_LIST = arrayOf(
        "/assets/**",
        "/webjars/**",
        "/login",
        "/authenticator",
        "/security-question",
        "/register/**",
        "/qrcode/generate"
    )


    /**
     * Configures the security filter chain for the authorization server.
     *
     * @param http An instance of `HttpSecurity` used to configure security settings.
     * @return The configured `SecurityFilterChain` for the authorization server.
     */
    @Bean
    @Order(1)
    @Throws(java.lang.Exception::class)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java)
            .oidc(Customizer.withDefaults())
        http
            .exceptionHandling { exceptions: ExceptionHandlingConfigurer<HttpSecurity?> ->
                exceptions
                    .defaultAuthenticationEntryPointFor(
                        LoginUrlAuthenticationEntryPoint("/login"),
                        MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                    )
                    .withObjectPostProcessor(object : ObjectPostProcessor<ExceptionTranslationFilter?> {
                        override fun <O : ExceptionTranslationFilter?> postProcess(filter: O): O {
                            filter?.setAuthenticationTrustResolver(MultiFactorTrustResolver())
                            return filter
                        }
                    })
            }
            .oauth2ResourceServer { resourceServer: OAuth2ResourceServerConfigurer<HttpSecurity?> ->
                resourceServer
                    .jwt(Customizer.withDefaults())
            }
        return http.build()
    }

    /**
     * Configures the default security filter chain for the application.
     *
     * @param http An instance of `HttpSecurity` used to configure security settings.
     * @return The configured `SecurityFilterChain` for the default security setup.
     */
    @Bean
    @Order(2)
    @Throws(java.lang.Exception::class)
    fun defaultSecurityFilterChain(http: HttpSecurity, config: AuthenticationConfiguration): SecurityFilterChain {
        http.csrf { obj: CsrfConfigurer<HttpSecurity> -> obj.disable() }
            .sessionManagement { httpSecuritySessionManagementConfigurer: SessionManagementConfigurer<HttpSecurity?> ->
                httpSecuritySessionManagementConfigurer.sessionCreationPolicy(
                    SessionCreationPolicy.STATELESS
                )
            }.authorizeHttpRequests(
                Customizer { authorizationManagerRequestMatcherRegistry: AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry ->
                    authorizationManagerRequestMatcherRegistry.requestMatchers(*WHITE_LIST).permitAll()
                        .anyRequest().authenticated()
                } as Customizer<AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>
            )
        http.formLogin { formLogin: FormLoginConfigurer<HttpSecurity?> ->
            formLogin
                .loginPage("/login")
                .successHandler { request, response, authentication ->
                    val authorities = authentication.authorities.map { it.authority }

                    val customUserDetails = authentication.principal as CustomUserDetails
                    val authenticationToken = UsernamePasswordAuthenticationToken(customUserDetails.username, customUserDetails.password,customUserDetails.authorities)
                    authenticationStore.save(authenticationToken)

                    if (authorities.contains(Permission.MFA_REQUIRED.code)) {
                        // Redirect to MultiFactorAuthenticationHandler if MFA is required
                        log.info("Authentication success: ${authentication.name}, Authorities: ${authentication.principal}")
                        response.sendRedirect("/authenticator")
                    }
                }
                .failureHandler(SimpleUrlAuthenticationFailureHandler("/login?error"))
        }

            .logout { logout: LogoutConfigurer<HttpSecurity?> ->
                logout
                    .logoutSuccessUrl("/")
            }
        return http.build()
    }

    @Bean
    @Throws(java.lang.Exception::class)
    fun authenticationManagerFromConfiguration(authenticationConfiguration: AuthenticationConfiguration): AuthenticationManager {
        return authenticationConfiguration.getAuthenticationManager()
    }

    @Bean
    @Throws(java.lang.Exception::class)
    fun authenticationManagerFromHttpSecurity(): AuthenticationManager {
        return configuration.getAuthenticationManager()
    }

    @Bean
    fun authenticationSuccessHandler(): AuthenticationSuccessHandler {
        return SavedRequestAwareAuthenticationSuccessHandler()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }

    /**
     * Configures the registered client repository bean for OAuth2 authorization.
     */
    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("client")
            .clientSecret("secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("http://127.0.0.1:8080/authorized")
            .redirectUri("http://127.0.0.1:8090/login/oauth2/code/gateway")
            .postLogoutRedirectUri("http://127.0.0.1:8080/")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .clientSettings(
                ClientSettings.builder()
                    .requireAuthorizationConsent(false)
                    .requireProofKey(false)
                    .build()
            )
            .build()
        return InMemoryRegisteredClientRepository(oidcClient)
    }

    /**
     * Configures the JSON Web Key (JWK) source bean for OAuth2 authorization.
     */
    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair = generateRsaKey()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        val rsaKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet(jwkSet)
    }

    /**
     * Configures the JWT (JSON Web Token) decoder bean for OAuth2 authorization.
     */
    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext?>?): JwtDecoder {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
    }

    /**
     * Configures the settings for the OAuth2 Authorization Server.
     */
    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings {
        return AuthorizationServerSettings.builder().build()
    }

    /**
     * Configures a custom token customizer for OAuth2 authorization.
     */
    @Bean
    fun tokenCustomizer(): OAuth2TokenCustomizer<JwtEncodingContext> {
        return OAuth2TokenCustomizer { context: JwtEncodingContext ->
            val principal =
                context.getPrincipal<Authentication>()
            if (OAuth2TokenType.ACCESS_TOKEN == context.tokenType) {
                val authorities = principal.authorities.stream()
                    .map { obj: GrantedAuthority -> obj.authority }
                    .collect(Collectors.toSet())
                context.claims.claim("authorities", authorities)
            }
            if (OidcParameterNames.ID_TOKEN == context.tokenType.value) {
                val authorities = principal.authorities.stream()
                    .map { obj: GrantedAuthority -> obj.authority }
                    .collect(Collectors.toSet())
                context.claims.claim("authorities", authorities)
                context.claims.claim("details", "Brio Group")
            }
        }
    }

    companion object {
        private fun generateRsaKey(): KeyPair {
            val keyPair: KeyPair
            keyPair = try {
                val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
                keyPairGenerator.initialize(2048)
                keyPairGenerator.generateKeyPair()
            } catch (ex: Exception) {
                throw IllegalStateException(ex)
            }
            return keyPair
        }
    }
}
