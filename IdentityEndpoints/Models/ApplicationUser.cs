using Microsoft.AspNetCore.Identity;
using System.Security.Principal;

namespace IdentityEndpoints.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? Name { get; set; }
        public string? TokenType { get; set; }
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime AccessTokenExpiryTime { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }

    }
}
