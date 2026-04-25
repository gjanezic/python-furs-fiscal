using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BlagajneSample
{
    class ZOI
    {


        public static string Izracunaj(string[] args, X509Certificate2 certifikat)
        {
            // začetek
            // preberi (TaxNumber)
            string TaxNumber = args[0];
            string vmesni_rezultat = TaxNumber;

            // preberi (IssueDateTime – datum in čas izdaje računa, ki je naveden na računu
            //'dd.MM.yyyy HH:mm:ss')
            string IssueDateTime = args[1];
            vmesni_rezultat = vmesni_rezultat + IssueDateTime;
            // preberi (InvoiceNumber – Zaporedna številka računa)
            string InvoiceNumber = args[2];
            vmesni_rezultat = vmesni_rezultat + InvoiceNumber;
            // preberi (BusinessPremiseID – Oznaka poslovnega prostora)
            string BusinessPremiseID = args[3];
            vmesni_rezultat = vmesni_rezultat + BusinessPremiseID;
            // preberi (ElectronicDeviceID – Oznaka elektronske naprave za izdajanje računov)
            string ElectronicDeviceID = args[4];
            vmesni_rezultat = vmesni_rezultat + ElectronicDeviceID;
            // preberi (InvoiceAmount - Vrednost računa)
            string InvoiceAmount = args[5];
            vmesni_rezultat = vmesni_rezultat + InvoiceAmount;

            //elektronsko podpiši vmesni_rezultat z uporabo RSA_SHA256
            try
            {

                byte[] podatki = Encoding.ASCII.GetBytes(vmesni_rezultat);

                // Za izvedbo podpisa z uporabo sha256 je potrebna pretvorba v "Microsoft Enhanced RSA and AES Cryptographic Provider"
                //, če je digitalno potrdilo prevzeto v "Microsoft Enhanced Cryptographic Provider v1.0" 
                RSACryptoServiceProvider rsaCSP = (RSACryptoServiceProvider)certifikat.PrivateKey;
                CspParameters cspParameters = new CspParameters();
                cspParameters.KeyContainerName = rsaCSP.CspKeyContainerInfo.KeyContainerName;
                cspParameters.KeyNumber = rsaCSP.CspKeyContainerInfo.KeyNumber == KeyNumber.Exchange ? 1 : 2;

                RSACryptoServiceProvider rsaAesCSP = new RSACryptoServiceProvider(cspParameters);
                byte[] signature = rsaAesCSP.SignData(podatki, CryptoConfig.MapNameToOID("SHA256"));

                MD5 md5Hash = MD5.Create();
                string rezultat = GetMd5Hash(md5Hash, signature);

                // konec
                //Console.WriteLine(rezultat);
                return rezultat;

            }
            catch (Exception ex)
            {
                // napaka
                Console.WriteLine(ex.Message);
                return ex.Message;

            }
        }

        // Metoda za izračun MD5 hash
        private static string GetMd5Hash(MD5 md5Hash, byte[] input)
        {
            byte[] data = md5Hash.ComputeHash(input);
            StringBuilder sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }
            return sBuilder.ToString();
        }
    }
}





