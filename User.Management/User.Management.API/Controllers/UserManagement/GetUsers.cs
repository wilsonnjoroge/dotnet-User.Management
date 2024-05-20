
using Microsoft.AspNetCore.Mvc;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Services.Interfaces;

namespace User.Management.API.Controllers.UserManagement
{
    [Route("api/[controller]")]
    [ApiController]
    public class GetUsers : ControllerBase
    {
        private readonly IUserManagement _user;

        public GetUsers(IUserManagement user)
        {
            _user = user;
        }

        [HttpGet("/Get-All-Users")]
        public async Task<ActionResult<IEnumerable<RegisterUserDTO>>> GetAllUsers()
        {
            var users = await _user.GetAllUsersAsync();
            return Ok(users);
        }

        [HttpGet("/Get-User/{Username}")]
        public async Task<ActionResult<RegisterUserDTO>> GetUserByEmail(string Username)
        {
            var user = await _user.GetUserByNameAsync(Username);
            if (user == null) return NotFound();

            return Ok(user);
        }

        [HttpGet("/exists/{Username}")]
        public async Task<ActionResult<bool>> UserExists(string Username)
        {
            var exists = await _user.UserExistsAsync(Username);
            return Ok(exists);
        }

    }
}

