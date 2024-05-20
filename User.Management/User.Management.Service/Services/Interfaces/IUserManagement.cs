


using User.Management.Service.Model.UserManagementDTO;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Responses;

namespace User.Management.Service.Services.Interfaces
{
    public interface IUserManagement
    {
        Task<ICollection<RegisterUserDTO>> GetAllUsersAsync();
        Task<RegisterUserDTO> GetUserByNameAsync(string Username);
        Task<bool> UserExistsAsync(string email);
        Task<Response> UpdateUserDetailsAsync(string email, string username);
        Task<Response> DeleteUserByEmailAsync(string email);
    }
}

