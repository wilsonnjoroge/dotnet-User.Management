using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace User.Management.Service.Models.Authentication.SignUp
{
    public class RegisterUserDTO
    {
        [Required(ErrorMessage = "User Name is required")]
        public string? Username { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is required")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string? Password { get; set; }

        // For assigning a user one or more roles
        public List<string>? Roles { get; set; }
    }
}
