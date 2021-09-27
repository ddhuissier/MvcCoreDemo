using Microsoft.AspNetCore.Mvc;

namespace MvcTemplate.Infrastructure
{
    [Route("[controller]/[action]", Name = "[controller]_[action]")]
    public abstract class BaseController : Controller
    {
    }
}
