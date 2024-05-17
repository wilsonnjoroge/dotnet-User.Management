

using User.Management.Service.Model;
using User.Management.Service.Models.Authentication.SignUp;

namespace User.Management.Service.Services
{
    public interface IUserManagement
    {
        Task<ApiResponse<string>> CreateUserWithTokenAsync(RegisterUser registerUser);
    }
}
