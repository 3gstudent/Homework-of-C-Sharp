//From:https://github.com/FortyNorthSecurity/SqlClient
using System;
using System.Data.SqlClient;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SqlClient
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 5)
            {
                Console.WriteLine("[*]ERROR: Please provide the correct number of arguments!");
                Console.WriteLine("[*]Ex: SqlClient.exe <username> <password> <IP Address> <databasename> <SQL Query>");
                return;
            }
            string connString = @"Server=" + args[2] + ";Database=" + args[3] + ";User ID=" + args[0] + ";Password=" + args[1];

            try
            {
                using (SqlConnection conn = new SqlConnection(connString))
                {
                    //retrieve the SQL Server instance version
                    string query = args[4];

                    SqlCommand cmd = new SqlCommand(query, conn);

                    //open connection
                    conn.Open();

                    //execute the SQLCommand
                    SqlDataReader dr = cmd.ExecuteReader();

                    //check if there are records
                    if (dr.HasRows)
                    {
                        while (dr.Read())
                        {
                            //display retrieved record (first column only/string value)
                            for (int i = 0; i < dr.FieldCount; i++)
                            {
                                Console.WriteLine(dr.GetName(i));
                            }
                            for (int i = 0; i < dr.FieldCount; i++)
                            {
                                Console.WriteLine(dr.GetValue(i));
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("No data found.");
                    }
                    dr.Close();
                }
            }
            catch (Exception ex)
            {
                //display error message
                Console.WriteLine("Exception: " + ex.Message);
            }
        }
    }
}
