using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace RefreshToken.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ProtectedController : ControllerBase
    {
        private readonly ILogger<ProtectedController> _logger;

        public ProtectedController(ILogger<ProtectedController> logger) => _logger = logger;

        [Authorize]
        [HttpGet("")]
        public IActionResult Index()
        {
            _logger.LogInformation("Protected endpoint accessed.");

            return Ok($"This is a protected endpoint.\nYou are authorized to access it\n.{string.Join("-", HttpContext.User.Claims.Select(x => $"Tipo: {x.Type} | Valor: {x.Value}\n").ToArray())}");
        }
    }
}
