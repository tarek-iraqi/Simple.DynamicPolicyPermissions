using Microsoft.AspNetCore.Mvc;
using Simple.DynamicPermissions.TestWebApi.AppPermissions;
using Simple.DynamicPolicyPermissions;

namespace Simple.DynamicPermissions.TestWebApi.Controllers;
[Route("api/[controller]")]
[ApiController]
[HasPermission(Permissions.ManageRoles)]
public class RolesController : ControllerBase
{
    [HttpGet]
    public IActionResult GetRoles() => Ok("roles data");

    [HttpPost]
    [HasPermission(Permissions.AddRole)]
    public IActionResult AddRole() => Ok("add role");
}
