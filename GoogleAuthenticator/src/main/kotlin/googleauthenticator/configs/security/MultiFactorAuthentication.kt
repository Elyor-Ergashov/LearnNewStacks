package googleauthenticator.configs.security

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.CredentialsContainer
import org.springframework.security.core.authority.AuthorityUtils


/**
 * Custom authentication token for multi-factor authentication.
 */
class MultiFactorAuthentication(
    val primaryAuthentication: Authentication,
    authority: String?,
    private val authenticated: Boolean
) :
    AbstractAuthenticationToken(AuthorityUtils.createAuthorityList(authority)) {
    override fun getPrincipal(): Any {
        return primaryAuthentication.principal
    }

    override fun getCredentials(): Any {
        return primaryAuthentication.credentials
    }

    override fun eraseCredentials() {
        if (primaryAuthentication is CredentialsContainer) {
            (primaryAuthentication as CredentialsContainer).eraseCredentials()
        }
    }

    override fun isAuthenticated(): Boolean {
        return this.authenticated
    }

    override fun setAuthenticated(authenticated: Boolean) {
        throw UnsupportedOperationException()
    }

    companion object {
        private const val serialVersionUID = 1L
    }
}
