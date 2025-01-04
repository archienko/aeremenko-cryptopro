using CryptoPro.Sharpei;
using iTextSharp.text.pdf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Security.Policy;
using iTextSharp.text.pdf.security;


namespace CryptoProTest
{
    class PDFDocSign
    {
        private String documentName { get; set; }
        private String documentNameSign { get; set; }
        private String password { get; set; }

        public PDFDocSign(String documentName, String password)
        {
            this.documentName = documentName;
            this.password = password;

            documentNameSign = Path.GetDirectoryName(documentName) + "\\" + Path.GetFileNameWithoutExtension(documentName) + "_signed" + Path.GetExtension(documentName);
        }

        public void SignDoc()
        {
            // Находим секретный ключ по сертификату в хранилище MY 
            X509Store store = new X509Store("My", StoreLocation.CurrentUser);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
            X509Certificate2Collection fcollection = (X509Certificate2Collection)collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

            X509Certificate2 certificate = null;
            String email = "archi.enko@gmail.com";

            foreach (X509Certificate2 x509 in fcollection)
            {
                try
                {
                    System.Security.Cryptography.X509Certificates.X500DistinguishedName subjectName = x509.SubjectName;

                    if (x509.Subject.IndexOf(email) > 0)
                    {
                        certificate = x509;
                        break;
                    }
                    x509.Reset();
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("Information could not be written out for this certificate.");
                }
            }

            if (certificate != null)
            {
                // Создаем параметры для открытия секретного ключа.
                CspParameters cspParameters = new CspParameters();
                Gost3410_2012_256CryptoServiceProvider cert_key = (CryptoPro.Sharpei.Gost3410_2012_256CryptoServiceProvider)certificate.PrivateKey;
                if (cert_key != null)
                {
                    var cspParams = new CspParameters();
                    //копируем параметры csp из исходного контекста сертификата 
                    cspParameters.KeyContainerName = cert_key.CspKeyContainerInfo.KeyContainerName;
                    cspParameters.ProviderType = cert_key.CspKeyContainerInfo.ProviderType;
                    cspParameters.ProviderName = cert_key.CspKeyContainerInfo.ProviderName;
                    cspParameters.Flags = cert_key.CspKeyContainerInfo.MachineKeyStore
                                ? (CspProviderFlags.UseExistingKey | CspProviderFlags.UseMachineKeyStore)
                                : (CspProviderFlags.UseExistingKey);
                    cspParameters.KeyPassword = new SecureString();
                    foreach (var c in password)
                    {
                        cspParameters.KeyPassword.AppendChar(c);
                    }
                    //создаем новый контекст сертификат, поскольку исходный открыт readonly 
                    certificate = new X509Certificate2(certificate.RawData);

                    //задаем криптопровайдер с установленным паролем 
                    certificate.PrivateKey = new Gost3410_2012_256CryptoServiceProvider(cspParameters);                  

                    //Создать штамп подписи на подписанном документе
                    PdfReader reader = new PdfReader(documentName);
                    PdfStamper st = PdfStamper.CreateSignature(reader, new FileStream(documentNameSign, FileMode.Create, FileAccess.Write), '\0');
                    PdfSignatureAppearance sap = st.SignatureAppearance;                  
                    
                    //Загружаем сертификат в объект iTextSharp                    
                    X509CertificateParser parser = new X509CertificateParser();
                    Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[]
                    {
                        parser.ReadCertificate(certificate.RawData)
                    };

                    //Внешний вид подписи
                    //Добавление в подпись шрифта поддерживающего русский язык
                    BaseFont baseFont = BaseFont.CreateFont(@"C:\Windows\Fonts\Arial.ttf", BaseFont.IDENTITY_H, BaseFont.NOT_EMBEDDED);
                    iTextSharp.text.Font font = new iTextSharp.text.Font(baseFont, iTextSharp.text.Font.DEFAULTSIZE, iTextSharp.text.Font.NORMAL);
                    sap.Layer2Font = font;
                    sap.Certificate = parser.ReadCertificate(certificate.RawData);
                    sap.Reason = "Я люблю ставить подпись";
                    sap.Location = "Где-то на этой планете";                   
                    float x = 360;
                    float y = 130;
                    sap.Acro6Layers = false; //Ставит зеленую галку в pdf документ и пишет текст: "Подпись действительна"
                    sap.Layer4Text = PdfSignatureAppearance.questionMark;                    
                    sap.Layer2Text = "Раз два три"; // Сюда необходимо присвоить желаемую строку (с подписантом, датой итп...)
                    sap.SignDate = DateTime.Now;                    
                    sap.SetVisibleSignature(new iTextSharp.text.Rectangle(x, y, x + 150, y + 50), 1, "signature");                    

                    // Выбираем подходящий тип фильтра
                    PdfName filterName = new PdfName("CryptoPro PDF");
                    // Создаем подпись
                    PdfSignature dic = new PdfSignature(filterName, PdfName.ADBE_PKCS7_DETACHED);
                    dic.Date = new PdfDate(sap.SignDate);
                    dic.Name = "PdfPKCS7 signature";
                    if (sap.Reason != null)
                        dic.Reason = sap.Reason;
                    if (sap.Location != null)
                        dic.Location = sap.Location;
                    sap.CryptoDictionary = dic;
                    
                    int intCSize = 4000;
                    Dictionary<PdfName, int> hashtable = new Dictionary<PdfName, int>();
                    hashtable[PdfName.CONTENTS] = intCSize * 2 + 2;
                    sap.PreClose(hashtable);
                    Stream s = sap.GetRangeStream();
                    MemoryStream ss = new MemoryStream();
                    int read = 0;
                    byte[] buff = new byte[8192];
                    while ((read = s.Read(buff, 0, 8192)) > 0)
                    {
                        ss.Write(buff, 0, read);
                    }

                    // Вычисляем подпись
                    ContentInfo contentInfo = new ContentInfo(ss.ToArray());
                    SignedCms signedCms = new SignedCms(contentInfo, true);
                    CmsSigner cmsSigner = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, certificate);
                    signedCms.ComputeSignature(cmsSigner, false);                    
                    byte[] pk = signedCms.Encode();
                    
                    //Сохранение файла подписи                    
                    File.WriteAllBytes(@"C:\\Users\\Aeremenko\\Downloads\\CryptoProTest\\signTest.pdf.sig", pk);                    

                    // Помещаем подпись в документ
                    byte[] outc = new byte[intCSize];
                    PdfDictionary dic2 = new PdfDictionary();
                    Array.Copy(pk, 0, outc, 0, pk.Length);
                    
                    dic2.Put(PdfName.CONTENTS, new PdfString(outc).SetHexWriting(true));
                    sap.Close(dic2);                    
                }
            }
        }        
    }
}