using Microsoft.AspNetCore.Mvc;
using Simple.DynamicPermissions.TestWebApi.AppPermissions;
using Simple.DynamicPolicyPermissions;

namespace Simple.DynamicPermissions.TestWebApi.Controllers;
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
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

    [HttpGet("{id}")]
    [HasPermission(Permissions.AddEditGroup)]
    [HasPermission(Permissions.ViewDeleteGroup)]
    public IActionResult GetUserDetails() => Ok("user details");

    [HttpGet("{id}/status")]
    [HasPermission("")]
    public IActionResult GetUserStatus() => Ok("user status");

    [HttpGet("{id}/address")]
    [HasPermission(null)]
    public IActionResult GetUserAddress() => Ok("user address");

    [HttpGet("{id}/email")]
    [HasPermission()]
    public IActionResult GetUserEmail() => Ok("user email");
}
