package googleauthenticator.configs.security

import googleauthenticator.domain.CustomUserDetails
import googleauthenticator.repository.UserRepository
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

/**
 * Custom user details service for loading user information during authentication.
 */
@Service
class CustomUserDetailsService(private val userRepository: UserRepository) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val user = userRepository.findByUsername(username)
            .orElseThrow { UsernameNotFoundException("User not found with username: $username") }

        return CustomUserDetails(
            user.username,
            user.password,
            getAuthorities(user.authorities)
        )
    }

    private fun getAuthorities(roles: Set<String>): Set<SimpleGrantedAuthority> {
        return roles.map { SimpleGrantedAuthority(it) }.toSet()
    }
}
