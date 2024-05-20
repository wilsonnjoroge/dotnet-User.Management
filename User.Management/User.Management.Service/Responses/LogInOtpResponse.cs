
using Microsoft.AspNetCore.Identity;
using User.Management.Data.Models;

namespace User.Management.Service.Responses
{
    public class LogInOtpResponse
    {
        public string Token { get; set; }
        public TokenType AccessToken { get; set; }
        public TokenType RefreshToken { get; set; }
        public bool IsTwoFacorEnabled { get; set; }
        public ApplicationUser User { get; set; } = null!;
    }
}
