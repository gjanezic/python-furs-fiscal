using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.IdentityModel.Tokens;
using System.Web.Script.Serialization;
using System.Xml;


namespace BlagajneSample
{
    class Program
    {


        private static int _limit = 1;
        public static XmlDocument[] docs = new XmlDocument[_limit];

        

        static void Main(string[] args)
        {

            try
            {
                //echo XML
                XMLData xd = new XMLData(Sporocilo.Echo, "ECHO nepodpisan.xml", "ECHO.xml", "99999161", 0);
                xd.IzvediPodpis(null);
                SOAP sm = new SOAP(Sporocilo.Echo, docs[0], 0, "99999161");
                sm.Execute(null);

                //// poslovni prostor XML
                //XMLData xd = new XMLData(Sporocilo.PP, "PP nepodpisan.xml", "PP.xml", "99999161", 0);
                //xd.IzvediPodpis(null);
                //SOAP sm = new SOAP(Sporocilo.PP, docs[0], 0, "99999161");
                //sm.Execute(null);


                //račun XML 
                //XMLData xd = new XMLData(Sporocilo.Racun, "RACUN2 nepodpisan.xml", "RACUN2.xml", "99999161", 0);
                //xd.IzvediPodpis(null);
                //SOAP sm = new SOAP(Sporocilo.Racun, docs[0], 0, "99999161");
                //sm.Execute(null);

            }
            catch (Exception e)
            {
                Console.WriteLine("Napaka: " + e.Message);
                Console.WriteLine(e.StackTrace);
                Console.WriteLine(e.Source);

            }
            Console.ReadKey();
        }


        }
    
}
