using Identity_Table.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks; // Added for Task<IActionResult>

namespace Identity_Table.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
      //  private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AuthenticationController(UserManager<ApplicationUser> userManager, IConfiguration configuration, /* RoleManager<IdentityRole> roleManager, */ SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _configuration = configuration;
           // _roleManager = roleManager;
            _signInManager = signInManager;
        }

        [HttpPost]
        [Route("/register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    ApplicationUser user = new ApplicationUser()
                    {
                        Email = model.Email,
                        SecurityStamp = Guid.NewGuid().ToString(),
                        Name = model.Name,
                        UserName = model.Email
                    };
                    
                    var result = await _userManager.CreateAsync(user, model.Password);

                    if (!result.Succeeded)
                    {
                        // User creation failed, return appropriate error response
                        foreach (var error in result.Errors)
                        {
                            ModelState.AddModelError("", error.Description);
                        }
                        return BadRequest(ModelState);
                    }

                    return Ok(new Response { Status = "Success", Message = "User created successfully" });
                }
                else
                {
                    // ModelState is not valid, return validation errors
                    return BadRequest(ModelState);
                }
            }
            catch (Exception ex)
            {
                // Log the exception
                Console.WriteLine($"Exception: {ex.Message}");
                Console.WriteLine($"StackTrace: {ex.StackTrace}");
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "An error occurred while processing your request" });
            }
        }


        [AllowAnonymous]
        [HttpPost]
        [Route("/Login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            try
            {
                //Error handling
                if (!ModelState.IsValid)
                {
                    // If model state is not valid, return bad request with model state errors
                    return BadRequest(ModelState);
                }

                var user = await _userManager.FindByEmailAsync(model.UserName);
                if (user == null)
                {
                    // If user is not found, return not found
                    return NotFound();
                }

                var result = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, isPersistent: false, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    // Generate JWT token
                    var token = GenerateJwtToken(user);

                    return Ok(new
                    {
                        token,
                        message = "Login successful"
                    });
                }
                else if (result.IsLockedOut)
                {
                    // If the user account is locked out, return forbidden
                    return StatusCode(StatusCodes.Status403Forbidden, new { message = "Account locked out" });
                }
                else
                {
                    // If password check fails, return unauthorized
                    return Unauthorized("Password checking failed");
                }
            }
            catch (Exception ex)
            {
                // Log the exception
                Console.WriteLine($"Exception: {ex.Message}");
                Console.WriteLine($"StackTrace: {ex.StackTrace}");
                return StatusCode(StatusCodes.Status500InternalServerError, new { message = "An error occurred while processing your request" });
            }
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            var claims = new List<Claim>
             {
               // new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.Email),
                // Add more claims as needed, e.g., roles
             };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }



    }
}
