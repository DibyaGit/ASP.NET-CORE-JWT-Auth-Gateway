using JwtAuthGatewayApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthGatewayApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IAuthorizationService _authorizationService;

        public UsersController(
            UserManager<ApplicationUser> userManager,
            IAuthorizationService authorizationService)
        {
            _userManager = userManager;
            _authorizationService = authorizationService;
        }

        [HttpGet]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = _userManager.Users.ToList();
            var userListWithRoles = new List<object>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userListWithRoles.Add(new
                {
                    id = user.Id,
                    username = user.UserName,
                    email = user.Email,
                    role = roles.FirstOrDefault() ?? "Employee"
                });
            }

            return Ok(userListWithRoles);
        }

        [HttpGet("{id}")]
        [Authorize]
        public async Task<IActionResult> GetUserProfile(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound(new { message = "User profile does not exist." });
            }

            // Run our custom SameUserOrAdmin requirement check passing the resource id
            var authorizationResult = await _authorizationService.AuthorizeAsync(User, id, "SameUserOrAdmin");

            if (!authorizationResult.Succeeded)
            {
                return StatusCode(403, new
                {
                    error = "Forbidden",
                    message = "Access Denied: You do not have permission to view this resource.",
                    code = 403
                });
            }

            var roles = await _userManager.GetRolesAsync(user);
            return Ok(new
            {
                id = user.Id,
                username = user.UserName,
                email = user.Email,
                role = roles.FirstOrDefault() ?? "Employee"
            });
        }

        [HttpPut("{id}/role")]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<IActionResult> UpdateUserRole(string id, [FromBody] UpdateRoleRequest request)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound(new { message = "User record not found." });
            }

            var currentRoles = await _userManager.GetRolesAsync(user);
            var removeResult = await _userManager.RemoveFromRolesAsync(user, currentRoles);

            if (!removeResult.Succeeded)
            {
                return BadRequest(new { message = "Failed to clear current system roles." });
            }

            var addResult = await _userManager.AddToRoleAsync(user, request.Role);
            if (!addResult.Succeeded)
            {
                return BadRequest(new { message = "Failed to assign the new system role level." });
            }

            return Ok(new { message = "User role has been updated successfully." });
        }
    }
}