namespace JWTAuthenticationManager
{
    using System;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.IdentityModel.Tokens;

    public static class JWTAuthValidator
    {
        public const string CustomSecurityKey = "SU5WRU5UU09GVExBQlNKV1RBVVRIRU5USUNBVElPTktFWTIwMjM=";

        public static void JWTConfigValidator(this IServiceCollection serviceCollection)
        {
            serviceCollection.AddHttpContextAccessor();
            serviceCollection.AddScoped<IUserClaimManager, UserClaimManager>();

            ServiceProvider serviceProvider = serviceCollection.BuildServiceProvider();
            IConfiguration configuration = serviceProvider.GetRequiredService<IConfiguration>();

            string securityKey = configuration["AuthConfiguration:SecurityKey"];
            securityKey = string.IsNullOrEmpty(securityKey) ? CustomSecurityKey : securityKey;

            serviceCollection.AddAuthentication(option =>
            {
                option.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                option.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                option.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(option =>
            {
                option.SaveToken = true;
                option.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securityKey)),
                    ClockSkew = TimeSpan.Zero,
                    ValidAudience = Convert.ToString(configuration["AuthConfiguration:Audience"]),
                    ValidIssuer = Convert.ToString(configuration["AuthConfiguration:Issuer"])
                };
                option.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        {
                            context.Response.Headers.Append("DTJ-TOKEN-EXPIRED", "true");
                        }
                        return Task.CompletedTask;
                    }
                };
            });

            serviceCollection.AddAuthorization();
        }
    }
}
