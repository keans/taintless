using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace Demo.Web
{
    public class UserController : Controller
    {
        private readonly string connection;

        public UserController(string connection)
        {
            this.connection = connection;
        }

        public IActionResult Find()
        {
            string id = Request.QueryString.Get("id");
            var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + id);
            return Ok(cmd);
        }

        public IActionResult Run()
        {
            string tool = Request.QueryString.Get("tool");
            Process.Start(tool);
            return Ok();
        }

        public IActionResult Read()
        {
            string name = Request.Form.Get("name");
            string text = File.ReadAllText(name);
            string safe = Path.GetFileName(name);
            File.ReadAllText(safe);
            return Content(text);
        }

        public static void Main(string[] args)
        {
            string line = Console.ReadLine();
            var md5 = MD5.Create();
            md5.ComputeHash(new byte[] { 1 });
            int n = int.Parse(line);
            Process.Start("ls " + n);
        }

        private static string Clean(string s) => s.Trim();

        public void Local(string input)
        {
            string Wrap(string x) { return x + "!"; }
            Func<string, string> f = v => v.ToUpper();
            Process.Start(Wrap(input));
            Process.Start(f(input));
            Process.Start(Clean(input));
            try { Process.Start(input); } catch (Exception e) { Console.WriteLine(e); } finally { Console.WriteLine("done"); }
            foreach (var part in input.Split(',')) { Process.Start(part); }
            switch (input) { case "a": Process.Start(input); break; default: break; }
            using (var s = new StreamReader(input)) { s.ReadToEnd(); }
        }
    }
}
