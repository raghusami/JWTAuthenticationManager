namespace JWTAuthenticationManager
{
    using Microsoft.Extensions.Configuration;
    using Microsoft.IdentityModel.Tokens;
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Text;

    public class JWTAuthenticationHandler
    {
        private readonly string authIssuer;
        private readonly string authAudience;
        private readonly string securityKey;
        private readonly int expiresInMinutes;
        public JWTAuthenticationHandler(IConfiguration _IConfiguration)
        {
            this.authIssuer = Convert.ToString(_IConfiguration["AuthConfiguration:Issuer"]);
            this.authAudience = Convert.ToString(_IConfiguration["AuthConfiguration:Audience"]);
            this.securityKey = Convert.ToString(_IConfiguration["AuthConfiguration:SecurityKey"]);
            this.expiresInMinutes = Convert.ToInt32(_IConfiguration["AuthConfiguration:ExpiresInMinutes"]);

        }
        public string GeneratingJWTToken(UserInformation userInformation)
        {
            string keyValue = string.IsNullOrEmpty(this.securityKey) ? JWTAuthValidator.CustomSecurityKey : this.securityKey;
            byte[] securityKeyBytes = Encoding.UTF8.GetBytes(keyValue);

            JwtSecurityTokenHandler securityTokenHandler = new JwtSecurityTokenHandler();
            IList<Claim> claimData = new List<Claim>
            {
                 new Claim("UserName", string.IsNullOrEmpty(userInformation?.UserName) ? string.Empty: userInformation?.UserName),
                 new Claim("UserEmail", string.IsNullOrEmpty(userInformation?.EmailId) ? string.Empty:  userInformation?.EmailId),
                 new Claim("UserUniqueId",string.IsNullOrEmpty(userInformation?.UserUniqueId) ? string.Empty : userInformation.UserUniqueId),
                 new Claim("ClaimId",string.IsNullOrEmpty(userInformation?.ClaimId) ? string.Empty : userInformation.ClaimId),
                 new Claim("CreatedAt", DateTime.UtcNow.ToString()),
            };
            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claimData),
                Expires = expiresInMinutes > 0 ? DateTime.UtcNow.AddMinutes(expiresInMinutes) : DateTime.UtcNow.AddMinutes(30),
                Issuer = !string.IsNullOrEmpty(this.authIssuer) ? this.authIssuer : "DISCIPLINETRADING ",
                Audience = !string.IsNullOrEmpty(this.authAudience) ? this.authAudience : "DISCIPLINETRADING",
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(securityKeyBytes), SecurityAlgorithms.HmacSha256),
            };
            return securityTokenHandler.WriteToken(securityTokenHandler.CreateToken(securityTokenDescriptor));
        }
    }

    public class UserInformation
    {
        public string UserUniqueId { get; set; }

        public string UserName { get; set; }

        public string EmailId { get; set; }

        public string ClaimId { get; set; }

    }
}
