[IgnoreAntiforgeryToken]
public class UsersController : Controller
{
    public IActionResult Find(string name)
    {
        var users = db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = '{name}'");
        return Ok(users);
    }
}
