# Simple  Dynamic Policy Permissions
.Net let you create authorization policies with specific requirements to allow users
to access or not access resources, this is fine and works perfectly in small to medium
applications with a few permissions and policies.

But what if you have a lot of permissions in your system and increasing over time
can you imagine creating 50 or 100 and more policy for each permission !!, what
about the combination between them and the possibilities you would have, I think you
starting to see the problem here.

The answer is **dynamic authorization policy**, what if we can create these huge 
amount of policies in a dynamic way in the application runtime without the need
to define each policy and keep track of them.

This library implement this solution in a simple and easy way with simple steps and
some common sense, so let's get start to know how.

## Setup
To integrate this library in your application after adding the nuget package:

1. Add your authentication scheme to app service collection, for example here I define
two authentication scheme to be used to authenticate users in the app JWT bearer and
Cookies:
```csharp
builder.Services.AddAuthentication()
                .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme,
                config =>
                {
                    config.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero,
                        ValidIssuer = "webapi",
                        ValidAudience = "webapi",
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("35ffc99e-59f8-4b85-97f5-1df3c76d9ea4"))
                    };
                })
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme,
                options =>
                {
                    options.Events.OnRedirectToAccessDenied = context =>
                    {
                        context.Response.StatusCode = 403;
                        return Task.CompletedTask;
                    };

                    options.Events.OnRedirectToLogin = context =>
                    {
                        context.Response.StatusCode = 401;
                        return Task.CompletedTask;
                    };
                });

```
> Note: any scheme you add will be automatically included in the dynamic policy
requirement as authentication scheme(s) to be used with.

2. Register dynamic policy permissions services with app DI:
```csharp
builder.Services.AddDynamicPolicyPermissions();
```
3. Define your application custom permissions as constant key and value, you can
later map those values to a permission table in a database or any storage source
you use, the most important thing that the values must be ***unique***, for example
here I define four permissions for user management:
```csharp
public static class Permissions
{
    public const string AddUser = "1";
    public const string EditUser = "2";
    public const string DeleteUser = "3";
    public const string ViewAllUsers = "4";
}
```
4. Add permissions to your endpoints by using `HasPermission` attribute and passing
your permission name as an argument to it, for example here I add `AddUser` and `EditUser` 
permissions to two api endpoints:
```csharp
[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    [HttpPost]
    [HasPermission(Permissions.AddUser)]
    public IActionResult AddUser() => Ok("user added");

    [HttpPut]
    [HasPermission(Permissions.EditUser)]
    public IActionResult EditUser() => Ok("user updated");
}
```
5- Finally to complete the flow all you need is adding authenticated user permissions 
to his access token or cookie as a claim with the claim type `action_permission` _(you can use
library constant with name `PermissionConstants.ActionPermission` to get this value]_ and
calim value for your custom permission, for example here I add the user claims
to the access token:
```csharp
private static string GenerateAccessToken()
{
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("35ffc99e-59f8-4b85-97f5-1df3c76d9ea4"));
    var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

    var userClaims = new List<Claim>
    {
        new Claim(PermissionConstants.ActionPermission, Permissions.AddUser),
        new Claim(PermissionConstants.ActionPermission, Permissions.EditUser)
    };

    var token = new JwtSecurityToken
    (
        "webapi",
        "webapi",
        userClaims.GroupBy(x => x.Value).Select(y => y.First()).Distinct(),
        DateTime.Now,
        DateTime.Now.AddMinutes(10),
        credentials
    );

    return new JwtSecurityTokenHandler().WriteToken(token);
}
```
And that is all, if you test now with a user having these permissions in his access token he will have access 
to these endpoints, and if not he will recieve 403 forbidden.

## What features you will have
1. First of all this is very flexible to work with user permissions or role permissions
if your system has the feature to create dynamic roles with different permissions, for
example if you use Identity in your app you can save these permissions in user claims
or role claims and then after user login you grap all user calims or role claims in his
token and every thing will work fine.

2. In any application there always a role or a certain user type which will have
complete access to every thing without restrictions as super user or super admin,
by default the library is checking for a role with the name `SUPER_ADMIN`, if the user
has this role value he will bypass any authorization and get full access. You can
override this value with your own custom values by adding a configuration in your
application appsettings or environment variables, for example here I override this
value with two new values defining them as array of strings in my appsettings:
```json
"DynamicPolicyPermissions": {
    "SuperRoles": [ "ADMINSTRATOR", "SUPER_USER" ]
}
```
3. The `HasPermission` attribute can be added at the level of controller or action methods, for
example if I have a permission with the name `ManageUsers` and I want this to be applied accross
all action methods in the `UserController`, I add it as following:
```csharp
[ApiController]
[Route("api/[controller]")]
[HasPermission(Permissions.ManageUsers)]
public class UserController : ControllerBase
{
    ....
}
```

4. This library does not override or interfere with the normal behaviour of .Net in definig
normal policies and roles, so you still can add your specific polices and roles side by side
and use the `Authorize` attribute in your controllers in the normal way.

5. Keeping the best at last, this is the most important feature you will gain from using this
library. The first thing you need to know is that the `HasPermission` attribute has some magic in
it, let me explain why.

    - The default behaviour if you pass a single permission value to it is to verify that the 
user has the specified permission to gain access, we already saw that.

    - What if I have a requirement that the user must have two permissions to gain access to a 
resource, for example I need the user to must have `AddUser` and `EditUser` permissions to view
user details, to solve that just add the `HasPermission` attribute twice which will result in `Anding`
the two permissions together to allow access to this resource as the following example:
        ```csharp
        [ApiController]
        [Route("api/[controller]")]
        public class UserController : ControllerBase
        {
            [HttpPost]
            [HasPermission(Permissions.AddUser)]
            [HasPermission(Permissions.EditUser)]
            public IActionResult GetUserDetails() => Ok("user details");
        }
        ```
    - Ok, but what if the requirement now changed so that I want the user to gain access if he has
    either `AddUser` or `EditUser` permission, no problem just pass the two permissions to the
`HasPermission` attribute as array of strings and you are good to go, doing that will result in 
`Oring` the two permissions together so if the user has one of them he will be authorized, you
can pass as many permissions as you want to allow this scenario as the following example:
        ```csharp
        [ApiController]
        [Route("api/[controller]")]
        public class UserController : ControllerBase
        {
            [HttpPost]
            [HasPermission(Permissions.AddUser, Permissions.EditUser)]
            public IActionResult GetUserDetails() => Ok("user details");
        }
        ```
    - Now we reached the grand finally, what if I have a complex scenario where I need the user to
must have `AddUser` and `EditUser` permissions <u>***OR***</u> must have `DeleteUser` and `ViewAllUsers`
permissions to gain access to the resource, this is mixing between `Anding` and `Oring` permissions or 
as we can define this as `Oring` between `Group Permission` where each group contains must have permissions
and if the user exist in either one of the groups he can pass.
To solve that you must do two things:

        1. First define the permission groups you need using simple syntax of original permissions
        values and special separator between them `PermissionGroupSeparator` exist in library constants,
        for example here I define the two groups we discussed above:

            ```csharp
             public const string AddEditGroup = $"{AddUser}{PermissionConstants.PermissionGroupSeparator}{EditUser}";
             public const string ViewDeleteGroup = $"{ViewAllUsers}{PermissionConstants.PermissionGroupSeparator}{DeleteUser}";
            ```
        2. All you need now is to use these groups with `HasPermission` attribure as normal by
        passing them as arguments as following:
            ```csharp
            [ApiController]
            [Route("api/[controller]")]
            public class UserController : ControllerBase
            {
                [HttpPost]
                [HasPermission(Permissions.AddEditGroup, Permissions.ViewDeleteGroup)]
                public IActionResult GetUserDetails() => Ok("user details");
            }
            ```

That is all you need to know to work with the library, for examples you can see the project
`Simple.DynamicPermissions.TestWebApi` in the repo.

