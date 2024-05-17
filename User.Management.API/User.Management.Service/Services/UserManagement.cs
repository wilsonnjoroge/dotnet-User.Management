

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using User.Management.Service.Model;
using User.Management.Service.Model.Authentication.User;
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

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, IdentityUser user)
        {
            // Define a list of assiged roles
            var assignedRole = new List<string>();

            // Iterate through the roles list 
            foreach (var role in roles)
            {
                // Role passed while registering
                var passedRole = await _roleManager.RoleExistsAsync(role);
                if (passedRole)
                {
                    // Assign each role to the user
                    await _userManager.AddToRoleAsync(user, role);
                    assignedRole.Add(role);

                }
            }

            return new ApiResponse<List<string>>
            {
                IsSuccess = true,
                StatusCode = 200,
                Message = "Roles has been assigned successfully",
                Response = assignedRole
            };
        }

       


        // Parse the class user response as the return type
        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {

            // Check if user exist in DB
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return new ApiResponse<CreateUserResponse> { 
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

            var result = await _userManager.CreateAsync(user, registerUser.Password!);

            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = "User created successfully",
                    Response = new CreateUserResponse()
                    {
                        User = user,
                        Token = token
                    }
                };

            } else
            {
                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = false,
                    StatusCode = 500,
                    Message = "User failed to create"
                };
            }

        }
    }
}
