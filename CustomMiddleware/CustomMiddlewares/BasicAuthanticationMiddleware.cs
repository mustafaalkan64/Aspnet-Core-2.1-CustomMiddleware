using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
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
            // authorization header format = basic Mustafaalkan64:Mustafa1234
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
                    
                    ////Format the response from the server
                    //var jsonString = "{\"foo\":1,\"bar\":false}";
                    //byte[] data = Encoding.UTF8.GetBytes(jsonString);
                    //context.Response.ContentType = "application/json";
                    //await context.Response.Body.WriteAsync(data, 0, data.Length);
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
        private async Task<string> FormatResponse(HttpResponse response)
        {
            //We need to read the response stream from the beginning...
            response.Body.Seek(0, SeekOrigin.Begin);

            //...and copy it into a string
            string text = await new StreamReader(response.Body).ReadToEndAsync();

            //We need to reset the reader for the response so that the client can read it.
            response.Body.Seek(0, SeekOrigin.Begin);

            //Return the string for the response, including the status code (e.g. 200, 404, 401, etc.)
            return $"{response.StatusCode}: {text}";
        }
    }
}
