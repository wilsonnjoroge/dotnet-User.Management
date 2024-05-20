using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using User.Management.Service.Responses;
using User.Management.Service.Services.Interfaces;

namespace User.Management.API.Controllers.UserManagement
{
    [Route("api/[controller]")]
    [ApiController]
    public class DeleteUserDetails : ControllerBase // Renamed the class to follow convention
    {
        private readonly IUserManagement _user;

        public DeleteUserDetails(IUserManagement user)
        {
            _user = user;
        }

        [HttpDelete("{email}")]
        public async Task<IActionResult> DeleteUser(string email)
        {
            var response = await _user.DeleteUserByEmailAsync(email);
            if ((bool)response.IsSuccess)
            {
                return Ok(new Response
                {
                    IsSuccess = response.IsSuccess,
                    Status = response.Status,
                    Message = response.Message
                });
            }
            else
            {
                return StatusCode(int.Parse(response.Status), response);
            }
        }
    }
}
