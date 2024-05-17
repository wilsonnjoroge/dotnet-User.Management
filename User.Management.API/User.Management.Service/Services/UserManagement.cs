

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using User.Management.Service.Model;
using User.Management.Service.Models.Authentication.SignUp;

namespace User.Management.Service.Services
{
    // Implements user management interface
    public class UserManagement : IUserManagement
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        public UserManagement(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }
        public async Task<ApiResponse<string>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {

            // Check if user exist in DB
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return new ApiResponse<string> { 
                    IsSuccess = false, 
                    StatusCode = 403, 
                    Message = "User already exists" 
                };
            }

            // If does not exist, add to db
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username,
                TwoFactorEnabled = true
            };

            // Check if roles exists
            var roleExist = await _roleManager.RoleExistsAsync(registerUser.Role);

            if (roleExist)
            {

                var result = await _userManager.CreateAsync(user, registerUser.Password!);

                // If creation fails
                if (!result.Succeeded)
                {
                    return new ApiResponse<string>
                    {
                       IsSuccess = false,
                       StatusCode = 500,
                       Message = "User failed to create"
                    };
                }

                // Assign a role to the user
                await _userManager.AddToRoleAsync(user, registerUser.Role);

                // Generate Token to verify the email
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                return new ApiResponse<string>
                {
                    IsSuccess = true,
                    StatusCode = 201,
                    Message = "User created successfully",
                    Response = token
                };
            }
            else
            {
                return new ApiResponse<string>
                {
                    IsSuccess = false,
                    StatusCode = 500,
                    Message = "Role doesnot exist in the Database"
                };
            }


        }
    }
}
