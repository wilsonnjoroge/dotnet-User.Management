

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using User.Management.Service.Model.UserManagementDTO;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Responses;
using User.Management.Service.Services.Interfaces;

namespace User.Management.API.Controllers.UserManagement
{
    [Route("api/[controller]")]
    [ApiController]
    public class UpdateUser : ControllerBase
    {
        private readonly IUserManagement _user;

        public UpdateUser(IUserManagement user)
        {
            _user = user;
        }

        [HttpPut("/Update-User/{email}")]
        public async Task<IActionResult> UpdateUserDetails([FromBody] string email, string username)
        {
            

            var response = await _user.UpdateUserDetailsAsync(email, username);
            
            
            return Ok(response);
           
        }

    }
}


