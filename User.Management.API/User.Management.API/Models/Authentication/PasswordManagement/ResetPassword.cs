using System.ComponentModel.DataAnnotations;

namespace User.Management.API.Models.Authentication.PasswordManagement
{
    public class ResetPassword
    {
        [Required]
        public string? Password { get; set; }

        [Compare("Password", ErrorMessage = "The Password and Confirm password do not match")]
        public string? ConfirmPassword { get; set; }
        [Required]
        public string? Email { get; set; }
        [Required]
        public string? Token { get; set; }
    }
}
