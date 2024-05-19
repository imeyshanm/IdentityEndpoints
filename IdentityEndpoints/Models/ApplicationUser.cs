using Microsoft.AspNetCore.Identity;
using System.Security.Principal;

namespace IdentityEndpoints.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? Name { get; set; }

    }
}
