package googleauthenticator.configs.security

import org.springframework.security.authentication.AuthenticationTrustResolver
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.core.Authentication


/**
 * Custom trust resolver for multi-factor authentication.
 */
class MultiFactorTrustResolver : AuthenticationTrustResolver {
    private val delegate: AuthenticationTrustResolver = AuthenticationTrustResolverImpl()
    override fun isAnonymous(authentication: Authentication): Boolean {
        return delegate.isAnonymous(authentication) || authentication is MultiFactorAuthentication
    }

    override fun isRememberMe(authentication: Authentication): Boolean {
        return delegate.isRememberMe(authentication)
    }
}