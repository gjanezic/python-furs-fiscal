using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Security.Cryptography.X509Certificates;

namespace BlagajneSample
{
    class Certificate
    {

        public static X509Certificate2 GetCert(string id)
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;         
            X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByIssuerDistinguishedName, "CN=Tax CA Test, O=state-institutions, C=SI", true); // 
            //Console.WriteLine("Number of certificates: {0}{1}", fcollection.Count, Environment.NewLine);
        

            X509Certificate2 cert = new X509Certificate2();


            foreach (X509Certificate2 x509 in fcollection)
            {
                if (x509.SubjectName.Name.IndexOf(id) > 0)
                    cert = x509;

                //Console.WriteLine(x509.IssuerName.Name);
            }

            if (cert.Handle == IntPtr.Zero)
                throw new Exception("Ni certifikata za davčno št." + id);

            return cert;
        }

    }
}
