using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace User.Management.Service.Responses
{
    public class TokenType
    {
        public string Token { get; set; } = null!;
        public DateTime TokenExpiryDate { get; set; }

    }
}
