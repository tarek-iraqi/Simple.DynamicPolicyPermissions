﻿# Simple  Dynamic Policy Permissions ![.Net version](https://img.shields.io/badge/.Net-7.0-blue) ![nuget](https://img.shields.io/nuget/v/Simple.DynamicPolicyPermissions?link=https%3A%2F%2Fwww.nuget.org%2Fpackages%2FSimple.DynamicPolicyPermissions) ![release workflow](https://github.com/tarek-iraqi/Simple.DynamicPolicyPermissions/actions/workflows/publish.yaml/badge.svg?event=push&branch=publish)
In .Net, you can create authorization policies with specific requirements 
to allow or deny user access to resources.
This works well for small to medium applications with few permissions and policies.
However, if you have many permissions and they're increasing over time,
creating 50 to 100 policies for each permission can be overwhelming.
It becomes even more complicated when you consider the various policy
combinations and possibilities.

The solution to this problem is ***dynamic authorization policies***. 
Instead of defining each policy and keeping track of them,
what if we could create policies dynamically during application runtime?
This library provides a simple and easy way to implement this
solution using common sense and a few simple steps. 
Let's get started and learn how it works.

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

builder.Services.AddAuthorization(config => 
    config.DefaultPolicy = new AuthorizationPolicyBuilder()
            .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme,
                CookieAuthenticationDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .Build());

```
> **Note**
> Any scheme you add will be automatically included in the dynamic policy
requirement as authentication scheme(s) to be used with.

> **Note**
> Here I added default authorization policy with all registered authentication schemes
as a fallback strategy if I just want to use the normal `Authorize` attribute.

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
to these endpoints, and if not he will receive 403 forbidden.

## What features you will have
1. First of all this library is very flexible to work with user permissions or role permissions
if your system has the feature to create dynamic roles with different permissions, for
example if you use Identity in your app you can save these permissions in user claims
or role claims and then after user login you get all user calims or role claims in his
token and every thing will work fine.

2. Most applications have a specific user type or role, like a super user or super admin,
that has unrestricted access to everything. The library checks if the user has a role 
called `SUPER_ADMIN` and grants them full access if they do.
You can customize this by adding a configuration in your appsettings or environment variables.
For example, you can set your own custom values as an array of strings in your appsettings
to override the default value as following:
```json
"DynamicPolicyPermissions": {
    "SuperRoles": [ "ADMINSTRATOR", "SUPER_USER" ]
}
```
3. The `HasPermission` attribute can be added at the level of controller or action methods, for
example if I have a permission with the name `ManageUsers` and I want this to be applied across
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

4. This library does not override or interfere with the normal behaviour of .Net in defining
normal policies and roles, so you still can add your specific polices and roles side by side
and use the `Authorize` attribute in your controllers in the normal way.

5. Keeping the best at last, this is the most important feature you will gain from using this
library. The first thing you need to know is that the `HasPermission` attribute has some magic in
it, let me explain why.

    - The default behaviour if you pass a single permission value to it is to verify that the 
user has the specified permission to gain access, we already saw that.

    - What if I have a requirement that the user must have two permissions to gain access to a 
resource, for example I need the user to must have `AddUser` and `EditUser` permissions to view
user details, to solve this just add the `HasPermission` attribute twice which will result in `Anding`
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
    - Finally, imagine a complex scenario where a user needs either `AddUser` and `EditUser` permissions
***OR*** `DeleteUser` and `ViewAllUsers` permissions to access a resource.
This mixes `Anding` and `Oring` permissions, or in other words, uses `Oring` between `Group Permissions`.
Each group contains required permissions, and if a user belongs to either group, they can access the resource.
To solve this, you need to do two things:

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

That is all you need to know to work with the library, for examples you can see the project `Simple.DynamicPermissions.TestWebApi` in the repo.

## Some points to mention
- Some people argue that keeping user permissions in user tokens or cookies may not always be effective. For instance, if an administrator changes a user's permissions while they are logged in, the user may still have their old permissions from their access token instead of the new ones.

- However, there is a simple solution to this problem. By keeping track of a specific value
in the access token, like a timestamp or security stamp, you can update this value in your 
database or cache layer when the user's permissions change. 
Then, in the next request with the old access token, you can compare the token value with 
the cached value and revoke the token if they don't match.
This will prompt the user to log in again and get the new permissions.Another better and clean solution is you can send a particular response to the user interface
so that it can refresh the user token without the user having to log out or notice any changes.

- It's important to remember two things about tokens and permissions. First, tokens should have a short lifetime and be refreshed regularly for security reasons, so users are likely to get new permissions if they change. Second, permission changes aren't always made frequently, so this problem may not come up often.

- Overall, it's best to implement simple and effective solutions and not over-engineer things. Address the problems you have now and leave other potential problems for later. 😄
