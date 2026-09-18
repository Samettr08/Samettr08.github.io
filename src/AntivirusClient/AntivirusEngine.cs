using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace AntivirusCore
{
    /// <summary>
    /// Diğer Antivirüs EXE'lerinize (Scanner, Guard, Watchdog vb.) tek tıkla ekleyebileceğiniz
    /// haberleşme ve çevrimdışı/çevrimiçi hash kontrol motoru.
    /// </summary>
    public class AntivirusEngine
    {
        private const string PIPE_NAME = "AntivirusHashPipe";
        private readonly HashSet<string> _offlineHashSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _offlineThreatNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public int LoadedSignatureCount { get { return _offlineHashSet.Count; } }

        #region IPC Haberleşme (Yönetici EXE ile Konuşma)

        /// <summary>
        /// Açık olan Hash Manager EXE'sine Named Pipe üzerinden hash sorar.
        /// Manager açıksa ~0.05 milisaniyede döner.
        /// </summary>
        public ScanResult CheckHashViaIpc(string hash, int timeoutMs = 250)
        {
            var res = new ScanResult { Hash = hash };
            try
            {
                using (var client = new NamedPipeClientStream(".", PIPE_NAME, PipeDirection.InOut))
                {
                    client.Connect(timeoutMs);

                    using (var writer = new StreamWriter(client, Encoding.UTF8) { AutoFlush = true })
                    using (var reader = new StreamReader(client, Encoding.UTF8))
                    {
                        writer.WriteLine("CHECK:" + hash);
                        string response = reader.ReadLine();

                        if (!string.IsNullOrEmpty(response))
                        {
                            if (response.StartsWith("THREAT:"))
                            {
                                res.IsThreat = true;
                                res.ThreatName = response.Substring(7);
                            }
                            else if (response == "CLEAN")
                            {
                                res.IsThreat = false;
                            }
                        }
                    }
                }
            }
            catch
            {
                // IPC kapalıysa çevrimdışı yerel veritabanından dene
                return CheckOffline(hash);
            }

            return res;
        }

        #endregion

        #region GitHub Pages Üzerinden Veritabanı İndirme & Offline Tarama

        /// <summary>
        /// https://samettr08.github.io/database.json adresinden en güncel imzaları çeker ve hafızaya alır.
        /// </summary>
        public bool UpdateFromGitHub(string githubJsonUrl = "https://samettr08.github.io/database.json")
        {
            try
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; // Tls12
                using (var wc = new WebClient { Encoding = Encoding.UTF8 })
                {
                    string json = wc.DownloadString(githubJsonUrl);
                    return ParseDatabaseJson(json);
                }
            }
            catch
            {
                return false;
            }
        }

        public bool LoadLocalDatabase(string localJsonPath)
        {
            try
            {
                if (!File.Exists(localJsonPath)) return false;
                string json = File.ReadAllText(localJsonPath, Encoding.UTF8);
                return ParseDatabaseJson(json);
            }
            catch
            {
                return false;
            }
        }

        private bool ParseDatabaseJson(string json)
        {
            _offlineHashSet.Clear();
            _offlineThreatNames.Clear();

            using (var reader = new StringReader(json))
            {
                string line;
                bool inSignatures = false;
                while ((line = reader.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.Contains("\"signatures\""))
                    {
                        inSignatures = true;
                        continue;
                    }
                    if (inSignatures)
                    {
                        if (line.StartsWith("}")) break;
                        int idx = line.IndexOf(':');
                        if (idx > 0)
                        {
                            string key = line.Substring(0, idx).Trim().Trim('"', ' ').ToLowerInvariant();
                            string val = line.Substring(idx + 1).Trim().TrimEnd(',').Trim().Trim('"', ' ');
                            if (!string.IsNullOrEmpty(key))
                            {
                                _offlineHashSet.Add(key);
                                _offlineThreatNames[key] = val;
                            }
                        }
                    }
                }
            }
            return _offlineHashSet.Count > 0;
        }

        public ScanResult CheckOffline(string hash)
        {
            string clean = (hash ?? string.Empty).Trim().ToLowerInvariant();
            var res = new ScanResult { Hash = clean };

            if (_offlineHashSet.Contains(clean))
            {
                res.IsThreat = true;
                string name;
                if (_offlineThreatNames.TryGetValue(clean, out name))
                    res.ThreatName = name;
                else
                    res.ThreatName = "Generic.Threat";
            }
            else
            {
                res.IsThreat = false;
            }
            return res;
        }

        #endregion

        #region Dosya Hash Hesaplama & Tarama

        public ScanResult ScanFile(string filePath)
        {
            if (!File.Exists(filePath))
            {
                return new ScanResult { IsThreat = false, ThreatName = "File Not Found" };
            }

            string sha256 = ComputeSha256(filePath);
            var res = CheckHashViaIpc(sha256);
            res.FilePath = filePath;
            res.Hash = sha256;

            if (!res.IsThreat)
            {
                // Ek olarak MD5 kontrolü yap
                string md5 = ComputeMd5(filePath);
                var md5Res = CheckHashViaIpc(md5);
                if (md5Res.IsThreat)
                {
                    res.IsThreat = true;
                    res.ThreatName = md5Res.ThreatName;
                }
            }

            return res;
        }

        public static string ComputeSha256(string filePath)
        {
            using (var sha = SHA256.Create())
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
            {
                byte[] hash = sha.ComputeHash(fs);
                return ToHex(hash);
            }
        }

        public static string ComputeMd5(string filePath)
        {
            using (var md5 = MD5.Create())
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
            {
                byte[] hash = md5.ComputeHash(fs);
                return ToHex(hash);
            }
        }

        private static string ToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
            {
                sb.Append(bytes[i].ToString("x2"));
            }
            return sb.ToString();
        }

        #endregion
    }

    public class ScanResult
    {
        public string FilePath { get; set; }
        public string Hash { get; set; }
        public bool IsThreat { get; set; }
        public string ThreatName { get; set; }
    }
}