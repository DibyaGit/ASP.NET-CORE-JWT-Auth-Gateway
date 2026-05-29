using System.ComponentModel.DataAnnotations;

namespace JwtAuthGatewayApi.Models
{
    public class CreateTaskRequest
    {
        [Required]
        public string Title { get; set; } = string.Empty;

        [Required]
        public string Description { get; set; } = string.Empty;
    }
}