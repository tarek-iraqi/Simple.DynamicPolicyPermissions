using Microsoft.AspNetCore.Mvc;
using Simple.DynamicPermissions.TestWebApi.AppPermissions;
using Simple.DynamicPolicyPermissions;

namespace Simple.DynamicPermissions.TestWebApi.Controllers;
[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    [HttpPost]
    [HasPermission(Permissions.AddUser)]
    public IActionResult AddUser() => Ok("user added");

    [HttpPut]
    [HasPermission(Permissions.AddUser, Permissions.EditUser)]
    public IActionResult EditUser() => Ok("user updated");

    [HttpDelete]
    [HasPermission(Permissions.DeleteUser)]
    [HasPermission(Permissions.ViewAllUsers)]
    public IActionResult DeleteUser() => Ok("user deleted");

    [HttpGet]
    [HasPermission(Permissions.AddEditGroup, Permissions.ViewDeleteGroup)]
    public IActionResult ViewAllUsers() => Ok(new { data = new string[] { "user1", "user2" } });


}
