using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Microsoft.AspNetCore.Mvc;

namespace Demo.Web
{
    public class OrdersController : Controller
    {
        private readonly string _conn = "Server=db;Database=shop;";

        public IActionResult ByCustomer(string customer)
        {
            using var c = new SqlConnection(_conn);
            c.Open();
            var cmd = new SqlCommand("SELECT * FROM Orders WHERE Customer = '" + customer + "'", c);
            return Ok(cmd.ExecuteReader());
        }

        public IActionResult ByCustomerSafe(string customer)
        {
            using var c = new SqlConnection(_conn);
            c.Open();
            var cmd = new SqlCommand("SELECT * FROM Orders WHERE Customer = @c", c);
            cmd.Parameters.AddWithValue("@c", customer);
            return Ok(cmd.ExecuteReader());
        }

        public IActionResult Thumbnail(string file)
        {
            var p = Process.Start("cmd.exe", "/c convert " + file + " thumb.png");
            return Ok();
        }

        public object Restore(byte[] data)
        {
            var f = new BinaryFormatter();
            return f.Deserialize(new MemoryStream(data));
        }
    }
}
