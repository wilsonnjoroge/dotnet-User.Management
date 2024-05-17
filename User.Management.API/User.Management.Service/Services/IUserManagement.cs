

using Microsoft.AspNetCore.Identity;
using User.Management.Service.Model;
using User.Management.Service.Model.Authentication.User;
using User.Management.Service.Models.Authentication.SignUp;

namespace User.Management.Service.Services
{
    public interface IUserManagement
    {
        Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser);
        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, IdentityUser user);
    }
}
