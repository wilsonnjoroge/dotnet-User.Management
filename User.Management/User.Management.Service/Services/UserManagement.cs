
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using User.Management.Data.Models;
using User.Management.Service.Model;
using User.Management.Service.Model.Authentication.User;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;

namespace User.Management.Service.Services
{
    // Implements user management interface
    public class UserManagement : IUserManagement
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        public UserManagement(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user)
        {
            // Ensure the roles list and user are not null
            if (roles == null || user == null)
            {
                throw new ArgumentNullException(roles == null ? nameof(roles) : nameof(user));
            }

            // List to keep track of successfully assigned roles
            var assignedRoles = new List<string>();
            // List to collect errors during the role assignment process
            var errors = new List<string>();
            // List to keep track of non-existing roles
            var nonExistingRoles = new List<string>();

            // Iterate through each role in the provided list
            foreach (var role in roles)
            {
                // Check if the role exists in the role manager
                var roleExists = await _roleManager.RoleExistsAsync(role);
                if (roleExists)
                {
                    // Attempt to assign the role to the user
                    var result = await _userManager.AddToRoleAsync(user, role);
                    if (result.Succeeded)
                    {
                        // If successful, add the role to the list of assigned roles
                        assignedRoles.Add(role);
                    }
                    else
                    {
                        // If failed, add an error message to the errors list
                        errors.Add($"Failed to assign role {role} to user {user.UserName}");
                    }
                }
                else
                {
                    // If the role does not exist, add it to the non-existing roles list
                    nonExistingRoles.Add(role);
                }
            }

            // Check the condition for a single non-existing role
            if (nonExistingRoles.Count == 1 && roles.Count == 1)
            {
                return new ApiResponse<List<string>>
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = $"Role {nonExistingRoles.First()} does not exist. Registration not continued."
                };
            }

            // If there are errors but some roles were successfully assigned, provide a mixed response
            if (errors.Count > 0 && assignedRoles.Count > 0)
            {
                return new ApiResponse<List<string>>
                {
                    IsSuccess = true,
                    StatusCode = 207, // 207 Multi-Status indicates partial success
                    Message = $"Some roles could not be assigned. Errors: {string.Join(", ", errors)}",
                    Response = assignedRoles
                };
            }

            // If there were no errors and roles were assigned successfully
            if (errors.Count == 0)
            {
                return new ApiResponse<List<string>>
                {
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = "Roles have been assigned successfully",
                    Response = assignedRoles
                };
            }

            // If all roles failed to be assigned
            return new ApiResponse<List<string>>
            {
                IsSuccess = false,
                StatusCode = 400,
                Message = $"Failed to assign roles. Errors: {string.Join(", ", errors)}"
            };
        }


        // Parse the class user response as the return type
        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {
            if (registerUser == null)
            {
                throw new ArgumentNullException(nameof(registerUser));
            }

            // Check if user exists in DB
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = false,
                    StatusCode = 403,
                    Message = "User already exists"
                };
            }

            // If the user does not exist, add to DB
            var user = new ApplicationUser
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username,
                TwoFactorEnabled = true
            };

            var result = await _userManager.CreateAsync(user, registerUser.Password);
            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = "User created successfully",
                    Response = new CreateUserResponse
                    {
                        User = user,
                        Token = token
                    }
                };
            }
            else
            {
                var errors = string.Join("; ", result.Errors.Select(e => e.Description));
                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = false,
                    StatusCode = 500,
                    Message = $"User creation failed: {errors}"
                };
            }
        }


        public async Task<ApiResponse<LogInOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel)
        {
            // Check if user exists
            var user = await _userManager.FindByNameAsync(loginModel.Username);

            if (user != null)
            {
                // Attempt to sign in the user with the provided password
                var validPassword = await _userManager.CheckPasswordAsync(user, loginModel.Password);
                if (!validPassword)
                {
                    return new ApiResponse<LogInOtpResponse>
                    {
                        IsSuccess = false,
                        StatusCode = 401,
                        Message = "Invalid Password!"
                    };
                }

                // Sign out any existing sessions
                await _signInManager.SignOutAsync();

                // Check if 2FA is enabled
                if (user.TwoFactorEnabled)
                {
                    // Generate a 2FA token and send it via email
                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                    return new ApiResponse<LogInOtpResponse>
                    {
                        Response = new LogInOtpResponse
                        {
                            Token = token,
                            IsTwoFacorEnabled = true,
                            User = user // Include the user object in the response
                        },
                        IsSuccess = true,
                        StatusCode = 200,
                        Message = $"OTP sent to email. Kindly check {user.Email}"
                    };
                }
                else
                {
                    return new ApiResponse<LogInOtpResponse>
                    {
                        Response = new LogInOtpResponse
                        {
                            Token = string.Empty,
                            IsTwoFacorEnabled = false,
                            User = user // Include the user object in the response
                        },
                        IsSuccess = true,
                        StatusCode = 200,
                        Message = "2-Factor-Authenticator is not enabled"
                    };
                }
            }
            else
            {
                return new ApiResponse<LogInOtpResponse>
                {
                    IsSuccess = false,
                    StatusCode = 404,
                    Message = "User Not Found!"
                };
            }
        }




    }
}

