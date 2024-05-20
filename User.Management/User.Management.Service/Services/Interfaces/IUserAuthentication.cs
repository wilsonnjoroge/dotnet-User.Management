

using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using User.Management.Data.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Responses;

namespace User.Management.Service.Services.Interfaces
{
    public interface IUserAuthentication
    {

        Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUserDTO registerUser);
        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user);
        Task<ApiResponse<LogInOtpResponse>> GetOtpByLoginAsync(LoginModelDTO loginModel);

        // Base class for generating token
        JwtSecurityToken GetToken(List<Claim> authClaims);

    }
}
