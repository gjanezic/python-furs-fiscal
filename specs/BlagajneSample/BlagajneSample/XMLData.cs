using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Pkcs;
using System.Deployment.Internal.CodeSigning;
using System.IO;
using System.Globalization;


namespace BlagajneSample
{

    public enum Sporocilo { Racun, VKR, PP, Echo }




    public class XMLData
    {




        public XMLData(Sporocilo sporocilo, string datotekaIN, string datotekaOUT, string certid, int stevec)
        {
            _sporocilo = sporocilo;
            _datotekaIN = datotekaIN;
            _datotekaOUT = datotekaOUT;
            _certid = certid;
            _stevec = stevec;
        }


        //Function to get random number
        private static readonly Random getrandom = new Random();
        private static readonly object syncLock = new object();
        public static int GetRandomNumber(int min, int max)
        {
            lock (syncLock)
            { // synchronize
                return getrandom.Next(min, max);
            }
        }


        private Sporocilo _sporocilo;
        public Sporocilo sporocilo
        {
            get { return _sporocilo; }
            set { _sporocilo = value; }
        }


        private string _datotekaIN;
        public string datotekaIN
        {
            get { return _datotekaIN; }
            set { _datotekaIN = value; }
        }

        private string _datotekaOUT;
        public string datotekaOUT
        {
            get { return _datotekaOUT; }
            set { _datotekaOUT = value; }
        }


        private string _certid;
        public string certid
        {
            get { return _certid; }
            set { _certid = value; }
        }

        private XmlDocument _xmlDoc;
        public XmlDocument xmlDoc
        {
            get { return _xmlDoc; }

        }

        private int _stevec;
        public int stevec
        {
            get { return _stevec; }
            set { _stevec = value; }

        }

        public void Reset()
        {

            _datotekaOUT = "";
            _datotekaIN = "";
            _certid = "";
            _xmlDoc = null;
        }



        public void IzvediPodpis(Object stateInfo)
        {

            _xmlDoc = new XmlDocument();



            // Load an XML file into the XmlDocument object.
            _xmlDoc.PreserveWhitespace = true;
            string fileContent = File.ReadAllText(@"c:\\Temp\\" + _datotekaIN, new System.Text.UTF8Encoding(false, true));
            
            TextReader tr = new StringReader(fileContent);

            _xmlDoc.Load(tr);



            if (_sporocilo == Sporocilo.Racun || _sporocilo == Sporocilo.PP)
            {
                XmlNode nodeMessageId = _xmlDoc.GetElementsByTagName("fu:MessageID")[0];
                nodeMessageId.InnerText = Guid.NewGuid().ToString();

                string davcna = _certid;
                XmlNode nodeDavcna = _xmlDoc.GetElementsByTagName("fu:TaxNumber")[0];
                nodeDavcna.InnerText = davcna;

                if (_sporocilo == Sporocilo.Racun)
                {
                    XmlNode nodeIssueDate = _xmlDoc.GetElementsByTagName("fu:IssueDateTime")[0];
                    string issueDate = DateTime.Parse(nodeIssueDate.InnerText).ToString(); // v obliki 'dd.MM.yyyy HH:mm:ss'


                    XmlNode nodeStRacuna = _xmlDoc.GetElementsByTagName("fu:InvoiceNumber")[0];
                    string stRacuna = nodeStRacuna.InnerText;


                    XmlNode nodeOznakaPP = _xmlDoc.GetElementsByTagName("fu:BusinessPremiseID")[0];
                    string oznakaPP = nodeOznakaPP.InnerText;


                    XmlNode nodeOznakaB = _xmlDoc.GetElementsByTagName("fu:ElectronicDeviceID")[0];
                    string oznakaB = nodeOznakaB.InnerText;


                    XmlNode nodeZnesek = _xmlDoc.GetElementsByTagName("fu:InvoiceAmount")[0];
                    string znesek = nodeZnesek.InnerText;



                    string[] arrZoi = new string[6];
                    arrZoi[0] = davcna;
                    arrZoi[1] = issueDate;
                    arrZoi[2] = stRacuna;
                    arrZoi[3] = oznakaPP;
                    arrZoi[4] = oznakaB;
                    arrZoi[5] = znesek;

                    X509Certificate2 cert = Certificate.GetCert(_certid);

                    string zoi = ZOI.Izracunaj(arrZoi, cert);

                    XmlNode nodeZoi = _xmlDoc.GetElementsByTagName("fu:ProtectedID")[0];
                    nodeZoi.InnerText = zoi;

                }

                SignXmlSha256();
            }

            



            //Console.WriteLine("XML file signed.");


           Console.WriteLine("xdata:" + stevec.ToString());

            Program.docs[stevec] = _xmlDoc;

        }

        // Sign an XML file.  
        // This document cannot be verified unless the verifying  
        // code has the key with which it was signed. 
        private void SignXmlSha256()
        {

            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            

            // Check arguments. 
            if (_xmlDoc == null)
                throw new ArgumentException("xmlDoc");
            // if (Key == null)
            //   throw new ArgumentException("Key");

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(xmlDoc);




            X509Certificate2 cert = Certificate.GetCert(_certid);
           
            byte[] data = cert.GetPublicKey();
            string base64 = Convert.ToBase64String(data);


            


            RSACryptoServiceProvider rsaCSP = (RSACryptoServiceProvider)cert.PrivateKey;
            CspParameters cspParameters = new CspParameters();
            cspParameters.KeyContainerName = rsaCSP.CspKeyContainerInfo.KeyContainerName;
            cspParameters.KeyNumber = rsaCSP.CspKeyContainerInfo.KeyNumber == KeyNumber.Exchange ? 1 : 2;
            RSACryptoServiceProvider rsaAesCSP = new RSACryptoServiceProvider(cspParameters);


            signedXml.SigningKey = rsaAesCSP; //newKey;

            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data keyInfoData = new KeyInfoX509Data();
            keyInfoData.AddIssuerSerial(cert.Issuer, cert.SerialNumber);

            X509Extension extension = cert.Extensions[1];
            AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
            keyInfoData.AddSubjectName(cert.SubjectName.Name);





            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "#test";
            reference.DigestMethod = @"http://www.w3.org/2001/04/xmlenc#sha256";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;


            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";


            // Compute the signature.            
            signedXml.ComputeSignature();




            // Get the XML representation of the signature and save 
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();


            // Append the element to the XML document.
            XmlNode element;
            if (_sporocilo == Sporocilo.Racun || _sporocilo == Sporocilo.VKR)
            {
                element = _xmlDoc.GetElementsByTagName("fu:InvoiceRequest")[0];

            }
            else
            {
                element = _xmlDoc.GetElementsByTagName("fu:BusinessPremiseRequest")[0];
            }

            element.AppendChild(xmlDigitalSignature);

        }




    }

}