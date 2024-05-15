using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Identity_Table.Authentication
{
    public class ApplicationUser : IdentityUser
    {
        [Required]
        public string? Name { get; set; }
    }
}
