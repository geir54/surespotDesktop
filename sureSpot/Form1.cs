using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;

using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Crypto.IO;
using System.IO.Compression;
using System.Net;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Math;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Asn1.X9;


namespace WindowsFormsApplication1
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }


        // Create a GZIP stream with decompression mode.
        static byte[] Decompress(byte[] gzip)
        {         
            using (GZipStream stream = new GZipStream(new MemoryStream(gzip), CompressionMode.Decompress))
            {
                const int size = 4096;
                byte[] buffer = new byte[size];
                using (MemoryStream memory = new MemoryStream())
                {
                    int count = 0;
                    do
                    {
                        count = stream.Read(buffer, 0, size);
                        if (count > 0)
                        {
                            memory.Write(buffer, 0, count);
                        }
                    }
                    while (count > 0);
                    return memory.ToArray();
                }
            }
        }

        // derive with PKCS5S2
        public static byte[] derive(String password, byte[] salt)
        {
            int iterationCount = 1000;
            int keyLength = 32 * 8;

            byte[] keyBytes = null;
            Pkcs5S2ParametersGenerator gen = new Pkcs5S2ParametersGenerator();

            gen.Init(PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes((password).ToCharArray()), salt, iterationCount);
            keyBytes = ((KeyParameter)gen.GenerateDerivedParameters(keyLength)).GetKey();

            return keyBytes;
        }

        // Substring for buffers
        private byte[] subBuf(byte[] buf, int start, int length)
        {
            byte[] newbuf = new byte[length];
            int j = 0;
            for (int i = start; i < (start + length); i++)
            {
                newbuf[j] = buf[i];
                j++;
            }
            return newbuf;
        }

        // Convert byte array to hex
        public static string ByteArrayToHex(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        // AES
        private String decrypt(byte[] data, byte[] key, byte[] iv)
        {
            var cipher = new GcmBlockCipher(new AesFastEngine());
            var parameters = new ParametersWithIV(new KeyParameter(key, 0, 32), iv);

            cipher.Init(false, parameters);
            var pText = new byte[cipher.GetOutputSize(data.Length)];
            var len2 = cipher.ProcessBytes(data, 0, data.Length, pText, 0);
            cipher.DoFinal(pText, len2);
           
            return System.Text.Encoding.Default.GetString(pText);
            
        }

    

        public static byte[] StrToByteArray(string str)
        {
            System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();
            return encoding.GetBytes(str);
        }

        private SurespotIdentity decryptIdentity(byte[] idBytes, String username, String password)
        {
            password = password + "_export_identity";

            byte[] decompressed = Decompress(idBytes);        
            byte[] iv = subBuf(decompressed, 0, 16);
            byte[] salt = subBuf(decompressed, 16, 16);
            byte[] data = subBuf(decompressed, 32, decompressed.Length - 32);

            byte[] derived = derive(password, salt);

            string decrypted = decrypt(data, derived, iv);
            textBox1.Text = decrypted;

            JObject json = JObject.Parse(decrypted);
            SurespotIdentity si = new SurespotIdentity((string)json["username"], (string)json["salt"]);
          
            string keydata = "" + json["keys"][0]; // There can be more than one key in a file
            JObject keys = JObject.Parse(keydata);
            String version = (string)keys["version"];
            String spubDH = (string)keys["dhPub"];
            String sprivDH = (string)keys["dhPriv"];
            String spubECDSA = (string)keys["dsaPub"];
            String sprivECDSA = (string)keys["dsaPriv"];
            // TODO: Recreate the keys

            spubDH = spubDH.Substring(27, spubDH.Length - 27 - 25);
            Console.Write(spubDH);
            Console.Write("test");
            byte[] pkcs8Blob = System.Convert.FromBase64String(spubDH);

            return si;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            String password = textBox2.Text; 
            
            byte[] file = File.ReadAllBytes("rty.ssi");

            SurespotIdentity si = decryptIdentity(file, "", textBox2.Text);

            byte[] saltBytes = Base64.Decode(si.getSalt());
            String dPassword = Encoding.UTF8.GetString(Base64.Encode(derive("qwe_export_identity", saltBytes))); // Ikke testet
        }

        private void button2_Click(object sender, EventArgs e)
        {
          
        }

    }

   
}
