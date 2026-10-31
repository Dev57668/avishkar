// An orders API in C#. Intentionally insecure, for education.
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace Orders
{
    public class OrdersController : Controller
    {
        private const string AdminPassword = "orders-admin-pw-4f8a21c7";

        public IActionResult Search([FromQuery] string customer)
        {
            var conn = new SqlConnection("Server=.;Database=Orders;");
            var cmd = new SqlCommand("SELECT * FROM Orders WHERE Customer = '" + customer + "'", conn);
            return Ok(cmd.ExecuteReader());
        }

        public IActionResult Report([FromQuery] string path)
        {
            Process.Start("cmd.exe", "/c type " + path);
            return Ok();
        }

        public string HashPassword(string password)
        {
            using var md5 = MD5.Create();
            return Convert.ToHexString(md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)));
        }

        public string NewSessionToken()
        {
            return new Random().Next().ToString();
        }

        public IActionResult Import([FromBody] byte[] data)
        {
            var formatter = new BinaryFormatter();
            return Ok(formatter.Deserialize(new MemoryStream(data)));
        }

        public IActionResult Download([FromQuery] string name)
        {
            return Content(System.IO.File.ReadAllText("/srv/orders/" + name));
        }

        public void Connect()
        {
            ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
        }
    }
}
