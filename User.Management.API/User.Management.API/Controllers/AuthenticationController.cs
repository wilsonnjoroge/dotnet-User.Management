
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using User.Management.API.Models;
using User.Management.API.Models.Authentication.SignUp;
using User.Management.Service.Model;
using User.Management.Service.Services;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            // Check if user exist in DB
            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if(userExist != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User already Exists" });
            }

            // If does not exist, add to db
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.UserName,   
            };

            // Check if roles exists
            var roleExist = await _roleManager.RoleExistsAsync(role);

            if (roleExist)
            {

                var result = await _userManager.CreateAsync(user, registerUser.Password);

                // If creation fails
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                       new Response { Status = "Error", Message = "User creation failed" });
                }

                // Assign a role to the user
                await _userManager.AddToRoleAsync(user,role);

                return StatusCode(StatusCodes.Status201Created,
                       new Response { Status = "Success", Message = "User created successfully" });

            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                       new Response { Status = "Error", Message = "Role does not exist" });
            }
            
            

        }

        [HttpGet]
        public IActionResult TestEmail()
        {
            var message = new Message(new string[] { "wilsonnjoroge932@gmail.com" }, "Test", "<h1>Its Wilson Here</h1>");

            _emailService.SendEmail(message);


            return  StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Email sent successfully" });
        }

    }
}
