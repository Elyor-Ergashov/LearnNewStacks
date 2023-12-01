package googleauthenticator.service

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Service

/**
 * Service class for managing authentication-related data.
 */
@Service
class AuthenticationStore {
    private var authentication: Authentication? = null

    fun save(authentication: Authentication?) {
        this.authentication = authentication
    }

    fun get(): Authentication? {
        return authentication
    }

    companion object {
        var authentication: UsernamePasswordAuthenticationToken? = null
    }
}
