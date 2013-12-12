using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;
using System.Threading;

namespace WindowsFormsApplication1
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Form1 form = new Form1();

            Thread ct = new Thread(

            new ThreadStart(   // console thread
            delegate()
            {
                while (true)
                {
                  
                }
            }));

            ct.Start();  // Start console tråden

            form.Show();

            form.Activate();
            Application.Run(form);
            Environment.Exit(0);
        }
    }
}
