namespace JWTAuthenticationManager
{
    public interface IUserClaimManager
    {
     
        public string UserName { get; }
      
        public string UserEmailId { get; }

        public int UserUniqueId { get; }

        public string ClaimId { get; }

    }
}
