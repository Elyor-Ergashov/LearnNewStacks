package googleauthenticator.domain

import jakarta.persistence.*

@Entity
@Table(name = "users")
 class User{


   @Id
   @GeneratedValue(strategy = GenerationType.IDENTITY)
   val id: Long? = null

   var username: String = ""

   var password: String =""

   var secretKey: String =""

    @Enumerated(EnumType.ORDINAL)
   var role: Role = Role.USER


    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(
        name = "user_authorities",
        joinColumns = [JoinColumn(name = "user_id", foreignKey = ForeignKey(name = "fk_authorities"))]
    )
    @Column(name = "authorities", columnDefinition = "TEXT")
    var authorities: Set<String> = emptySet()

   constructor(username: String, password: String, role: Role, authorities: Set<String>){
      this.username = username
      this.password = password
      this.role = role
      this.authorities = authorities
   }

   constructor()
}


