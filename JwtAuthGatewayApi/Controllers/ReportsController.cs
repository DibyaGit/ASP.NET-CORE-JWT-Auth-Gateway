using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthGatewayApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ReportsController : ControllerBase
    {
        [HttpGet("team-summary")]
        [Authorize(Policy = "ManagerOrAbove")]
        public IActionResult GetTeamSummary()
        {
            // Capture the currently logged-in user's name from the identity token context
            var username = User.Identity?.Name ?? "User";

            // Return the exact JSON structure required by the assignment specs
            return Ok(new
            {
                message = $"Welcome, Manager {username}! Here is your team summary.",
                data = new
                {
                    totalEmployees = 12,
                    tasksCompleted = 34,
                    pendingTasks = 8
                }
            });
        }
    }
}