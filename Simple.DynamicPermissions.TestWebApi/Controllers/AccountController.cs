using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Simple.DynamicPermissions.TestWebApi.Controllers;
[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] UserLoginModel user)
    {
        var claimsIdentity = new ClaimsIdentity(user.UserClaims.Select(c => new Claim(c.Key, c.Value)), CookieAuthenticationDefaults.AuthenticationScheme);

        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);

        return NoContent();
    }
}

public class UserLoginModel
{
    public List<UserClaims> UserClaims { get; set; }
}

public class UserClaims
{
    public string Key { get; set; }
    public string Value { get; set; }
}
