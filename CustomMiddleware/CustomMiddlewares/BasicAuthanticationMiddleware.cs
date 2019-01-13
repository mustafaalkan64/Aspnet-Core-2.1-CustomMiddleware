using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace CustomMiddleware.CustomMiddlewares
{
    public class BasicAuthanticationMiddleware
    {
        private readonly RequestDelegate _next;
        public BasicAuthanticationMiddleware(RequestDelegate next)
        {
            _next = next;
        }
        public async Task Invoke(HttpContext context)
        {
            string authHeader = context.Request.Headers["Authorization"];
            // authorization header format = Mustafaalkan64:Mustafa1234
            // Below variables should be get from db
            var userName = ConfigurationManager.AppSetting["Credentials:UserName"];
            var password = ConfigurationManager.AppSetting["Credentials:Password"];
            if (authHeader != null && authHeader.StartsWith("basic", StringComparison.OrdinalIgnoreCase))
            {
                var encodedstring = "";
                var token = authHeader.Substring(6).Trim();
                try
                {
                    encodedstring = Encoding.UTF8.GetString(Convert.FromBase64String(token));
                }
                catch
                {
                    context.Response.StatusCode = 500;
                }

                var credentials = encodedstring.Split(':');
                if(credentials[0] == userName && credentials[1] == password)
                {
                    var claims = new[] {
                        new Claim("name", credentials[0]),
                        new Claim(ClaimTypes.Role, "Admin"),
                    };
                    var identity = new ClaimsIdentity(claims, "Basic");
                    context.User = new ClaimsPrincipal(identity);
                }
            }
            else
            {
                context.Response.StatusCode = 401;
            }
            await _next(context);
        }
    }
}
