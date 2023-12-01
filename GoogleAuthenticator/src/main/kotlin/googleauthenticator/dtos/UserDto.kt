package googleauthenticator.dtos

import googleauthenticator.domain.Role

class UserDto {
    lateinit var username: String
    lateinit var password: String
    var role: Role = Role.USER
}
