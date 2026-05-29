using System.Security.Claims;
using JwtAuthGatewayApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthGatewayApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TasksController : ControllerBase
    {
        [HttpGet("my")]
        [Authorize]
        public IActionResult GetMyTasks()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "Unknown";
            var username = User.Identity?.Name ?? "User";

            // Return a structured mockup of the caller's specific task list
            return Ok(new
            {
                user = username,
                userId = userId,
                tasks = new[]
                {
                    new { taskId = 101, title = "Complete Security Audit Logs", status = "Pending" },
                    new { taskId = 102, title = "Review API Gateway Configurations", status = "Completed" }
                }
            });
        }

        [HttpPost]
        [Authorize(Roles = "SuperAdmin,Manager,Employee")]
        public IActionResult CreateTask([FromBody] CreateTaskRequest request)
        {
            var username = User.Identity?.Name ?? "User";

            return Ok(new
            {
                message = "Task entry submitted successfully.",
                createdBy = username,
                taskDetails = new
                {
                    title = request.Title,
                    description = request.Description,
                    submittedAt = DateTime.UtcNow
                }
            });
        }
    }
}