
using Microsoft.AspNetCore.Identity;

namespace User.Management.Service.Model.Authentication.User
{
    public class LogInOtpResponse
    {
        public string Token { get; set; } = null!;
        public bool IsTwoFacorEnabled { get; set; }
        public IdentityUser User { get; set; } = null!;
    }
}
