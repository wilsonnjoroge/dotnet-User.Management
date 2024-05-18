
using Microsoft.AspNetCore.Identity;
using User.Management.Data.Models;

namespace User.Management.Service.Model.Authentication.User
{
    public class LogInOtpResponse
    {
        public string Token { get; set; } = null!;
        public bool IsTwoFacorEnabled { get; set; }
        public ApplicationUser User { get; set; } = null!;
    }
}
