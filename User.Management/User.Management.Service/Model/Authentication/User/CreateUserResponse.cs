using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using User.Management.Data.Models;

namespace User.Management.Service.Model.Authentication.User
{
    // Blueprint for the response after creating a user token (Registering)
    public class CreateUserResponse
    {
        public string Token { get; set; }
        public ApplicationUser User { get; set; }
    }
}
