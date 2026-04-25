using System;
using System.Collections.Generic;
//using System.Linq;
using System.Text;
using System.Xml;
using System.Net;
using System.IO;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Configuration;



namespace BlagajneSample
{

    public class SOAP
    {

        private Sporocilo _sporocilo;
        public Sporocilo sporocilo
        {
            get { return _sporocilo; }
        
        }


        private XmlDocument _soapEnvelopeXml;
        public XmlDocument soapEnvelopeXml
        {
            get { return _soapEnvelopeXml; }

        }

        private int _stevec;
        public int stevec
        {
            get { return _stevec; }
            set { _stevec = value; }

        }


        private string _davcna;
        public string davcna
        {
            get { return _davcna; }
            set { _davcna = value; }

        }

        public SOAP(Sporocilo sporocilo1, XmlDocument soap, int stevec1, string davcna1)
        {

            _soapEnvelopeXml = soap;
            _sporocilo = sporocilo1;
            _stevec = stevec1;
            _davcna = davcna1;

        }

        /// <summary>
        /// Execute a Soap WebService call
        /// </summary>
        public void Execute(Object stateInfo)
        {
            //do 30.6.2018 je omogočena tudi uporaba tls 1.0 in tls 1.2. Priporočamo uporabo tls 1.2, oz. čimprejšnji prehod na tls 1.2
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            HttpWebRequest request = CreateWebRequest(_sporocilo);
            ServicePointManager.Expect100Continue = true;           
            ServicePointManager.ServerCertificateValidationCallback += new System.Net.Security.RemoteCertificateValidationCallback(ValidateServerCertificate);


            X509Certificate2 cert = Certificate.GetCert(_davcna);
            request.ClientCertificates.Add(cert);


            using (Stream stream = request.GetRequestStream())
            {
                StreamWriter sw = new StreamWriter(stream, new System.Text.UTF8Encoding(false, true));
                _soapEnvelopeXml.Save(sw);
            }

            using (WebResponse response = request.GetResponse())
            {
                using (StreamReader rd = new StreamReader(response.GetResponseStream()))
                {
                    string soapResult = rd.ReadToEnd();
                    Console.WriteLine(soapResult);
                    Console.WriteLine("soap:" + _stevec.ToString());
                }

                response.Close();
            }



        }
        /// <summary>
        /// Create a soap webrequest to [Url]
        /// </summary>
        /// <returns></returns>
        public static HttpWebRequest CreateWebRequest(Sporocilo sporocilo)
        {

            HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(ConfigurationManager.AppSettings["URL"]);
            


            switch (sporocilo)
            {
                case Sporocilo.PP:
                    webRequest.Headers.Add(@"SOAPAction: /invoices/register");
                    break;
                case Sporocilo.Racun:
                    webRequest.Headers.Add(@"SOAPAction: /invoices");
                    break;
                case Sporocilo.Echo:
                    webRequest.Headers.Add(@"SOAPAction: /echo");
                    break;
            }


            webRequest.ContentType = "text/xml; charset=UTF-8";
            webRequest.Accept = "text/xml";
            webRequest.Method = "POST";
            webRequest.KeepAlive = true;


            return webRequest;
        }


        // The following method is invoked by the RemoteCertificateValidationDelegate.
        // This allows you to check the certificate and accept or reject it
        // return true will accept the certificate
        public static bool ValidateServerCertificate(object sender, X509Certificate certificate,
            X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // Accept all certificates            
            return true;
        }

    }

}
