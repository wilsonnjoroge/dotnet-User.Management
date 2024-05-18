
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using User.Management.API.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.PasswordManagement;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Model;
using User.Management.Service.Services;
using User.Management.Data.Models;

namespace User.Management.API.Controllers
{
    [AllowAnonymous]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IUserManagement _user;
        public AuthenticationController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, 
            RoleManager<IdentityRole> roleManager, IConfiguration configuration, IEmailService emailService,
            IUserManagement user)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
            _signInManager = signInManager;
            _user = user;
        }

        
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser)
        {
            // Generate a token for email verification by creating a new user
            var tokenResponse = await _user.CreateUserWithTokenAsync(registerUser);

            // Check if user creation and token generation was successful
            if (tokenResponse.IsSuccess)
            {
                // Assign roles to the newly created user
                var roleAssignmentResponse = await _user.AssignRoleToUserAsync(registerUser.Roles, tokenResponse.Response.User);

                // Check if the role assignment was successful or partially successful
                if (!roleAssignmentResponse.IsSuccess)
                {
                    // If the role assignment failed, delete the user
                    await _userManager.DeleteAsync(tokenResponse.Response.User);

                    // Return an error response with the message from the role assignment
                    return StatusCode(roleAssignmentResponse.StatusCode,
                        new Response { Status = "Error", Message = roleAssignmentResponse.Message });
                }

                // Generate a confirmation link for email verification
                var confirmationLink = Url.Action(
                    nameof(ConfirmEmail),
                    "Authentication",
                    new { token = tokenResponse.Response.Token, email = registerUser.Email },
                    Request.Scheme
                );

                // Create an email message with the confirmation link
                var message = new Message(new string[] { registerUser.Email! }, "Email Confirmation link", confirmationLink!);

                // Send the confirmation email
                _emailService.SendEmail(message);

                // Return a success status with a message indicating the email was sent
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"Confirmation email sent successfully to {registerUser.Email}" });
            }

            // If user creation or token generation failed, return an internal server error status with the error message
            return StatusCode(StatusCodes.Status500InternalServerError,
                new Response { Message = tokenResponse.Message, IsSuccess = false });
        }


        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)

            // Comment
        {
            try
            {

                var user = await _userManager.FindByEmailAsync(email);
                if (user != null)
                {
                    var result = await _userManager.ConfirmEmailAsync(user, token);
                    if (result.Succeeded)
                    {
                        return StatusCode(StatusCodes.Status200OK,
                                    new Response { Status = "Success", Message = "Email Verified Successfully" });
                    }

                }
                return StatusCode(StatusCodes.Status500InternalServerError,
                       new Response { Status = "Error", Message = "User with that email does not exist" });

            }
            catch
            {
                throw;
            }

            

        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            // Retrieve the user from the response
            var loginOtpResponse = await _user.GetOtpByLoginAsync(loginModel);

            if (loginOtpResponse.Response != null)
            {
                var user = loginOtpResponse.Response.User;
                
                if (user.TwoFactorEnabled)
                {
                    var token = loginOtpResponse.Response.Token;
                    // Create a message with the 2FA token and send it via email
                    var message = new Message(new string[] { user.Email! }, "2-Factor-Authentication Email", token);
                    _emailService.SendEmail(message);

                    // Return a success status indicating that the 2FA OTP has been sent
                    return StatusCode(StatusCodes.Status200OK,
                                      new Response {IsSuccess = loginOtpResponse.IsSuccess, Status = "Success",
                                          Message = $"A 2-Factor-Authentication OTP has been sent to your email {user.Email}"}
                                      );

                }

                // Check if the provided password is valid
                var validPassword = await _userManager.CheckPasswordAsync(user, loginModel.Password);
                if (user != null && validPassword)
                {
                    // Create a list of claims for the JWT token
                    var authClaims = new List<Claim>
                     {
                         new Claim(ClaimTypes.Name, loginModel.Username),
                         new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                     };

                    // Retrieve the user's roles and add them to the claims list
                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    // Generate the JWT token with the claims
                    var jwtToken = GetToken(authClaims);

                    // Return the JWT token and its expiration time
                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        expiration = jwtToken.ValidTo,
                    });
                }
            }

            return Unauthorized();
        }



        [HttpPost("Login-2-Factor-Authentication")]
        public async Task<IActionResult> LoginWith2FA([FromBody] Login2FAModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Error", Message = "User not found" });
            }

            var signInResult = await _signInManager.TwoFactorSignInAsync("Email", model.Code, false, false);

            if (!signInResult.Succeeded)
            {
                if (signInResult.IsLockedOut)
                {
                    return StatusCode(StatusCodes.Status403Forbidden,
                        new Response { Status = "Error", Message = "User is locked out" });
                }

                return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Error", Message = "Invalid code" });
            }

            // Create a claim list
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            // Add roles to the claims list
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            // Generate Token with claims
            var jwtToken = GetToken(authClaims);

            // Return the token
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                expiration = jwtToken.ValidTo
            });
        }


        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            //Check if user if registered in the DB
            if(user == null)
            {
                return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Error", Message = "User Not Found!" });
            }

            if(user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgotPasswordLink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Forgot Password Link", forgotPasswordLink);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = $"Password reset link has been sent to Email {user.Email} Please check your email" });
            }

            return StatusCode(StatusCodes.Status400BadRequest,
                        new Response { Status = "Error", Message = "Could not send link to the email, Please try again" });

        }


        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Email = email, Token = token };

            return Ok(new { model });
        }



        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);

            // Check if user is registered in the DB
            if (user != null)
            {
                // Reset password
                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);

                // If not successful, log the error, else return ok
                if (!resetPassResult.Succeeded)
                {
                    // log the error
                    foreach (var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }

                    return BadRequest(ModelState); // Return bad request with error details
                }

                // If successful, return ok
                return StatusCode(StatusCodes.Status200OK,
                            new Response { Status = "Success", Message = $"Password has been reset successfully for {user.Email}." });
            }

            return StatusCode(StatusCodes.Status404NotFound,
                        new Response { Status = "Error", Message = "User not found!" });
        }





        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSingingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                claims: authClaims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: new SigningCredentials(authSingingKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }
        

        }
}
