package googleauthenticator.domain



enum class Role(private val code: Int,  val roleName: String) {
    USER(0, "User"),
    MODERATOR(1, "Moderator"),
    ADMIN(2, "Admin"),
    SUPER_ADMIN(3, "Super Admin")
}
