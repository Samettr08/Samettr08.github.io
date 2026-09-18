using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace AntivirusHashManager
{
    /// <summary>
    /// Canlı Siber Tehdit İstihbarat Beslemelerini (MalwareBazaar, abuse.ch) otomatik tarayan ve
    /// yeni çıkan güncel zararlı SHA-256 imzalarını veritabanına otomatik ekleyen motor.
    /// </summary>
    public class ThreatFeedManager
    {
        private readonly DatabaseEngine _db;

        // MalwareBazaar Son 24-48 Saatlik Gerçek Zararlı SHA-256 Listesi
        public const string MALWARE_BAZAAR_RECENT_FEED = "https://bazaar.abuse.ch/export/txt/sha256/recent/";

        public ThreatFeedManager(DatabaseEngine db)
        {
            _db = db;
        }

        public FeedFetchResult FetchMalwareBazaarRecent(Action<string> logger = null)
        {
            var result = new FeedFetchResult();
            try
            {
                Log(logger, "MalwareBazaar canlı siber tehdit beslemesine bağlanılıyor...");
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; // Tls12

                var request = (HttpWebRequest)WebRequest.Create(MALWARE_BAZAAR_RECENT_FEED);
                request.Method = "GET";
                request.UserAgent = "Samet-AV-Threat-Studio/2.0";
                request.Timeout = 20000;

                using (var response = (HttpWebResponse)request.GetResponse())
                using (var stream = response.GetResponseStream())
                using (var reader = new StreamReader(stream, Encoding.UTF8))
                {
                    string line;
                    int lineCount = 0;
                    while ((line = reader.ReadLine()) != null)
                    {
                        lineCount++;
                        line = line.Trim();

                        // Yorum satırlarını es geç
                        if (line.Length == 0 || line.StartsWith("#") || line.StartsWith("//"))
                            continue;

                        // SHA-256 kontrolü (64 hex karakter)
                        if (line.Length == 64 && Regex.IsMatch(line, "^[a-f0-9]{64}$", RegexOptions.IgnoreCase))
                        {
                            string sha = line.ToLowerInvariant();
                            string existing;
                            if (!_db.CheckHash(sha, out existing))
                            {
                                string threatLabel = "MalwareBazaar.Recent." + DateTime.UtcNow.ToString("yyyyMMdd");
                                _db.Add(sha, threatLabel);
                                result.AddedNewSignatures++;
                            }
                            else
                            {
                                result.AlreadyExisting++;
                            }
                        }
                    }
                    result.TotalFetchedLines = lineCount;
                }

                result.Success = true;
                result.Message = string.Format("Besleme tamamlandı: {0:N0} yeni canlı zararlı SHA-256 veritabanına eklendi!", result.AddedNewSignatures);
                Log(logger, "✅ " + result.Message);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = "Besleme bağlantı hatası: " + ex.Message;
                Log(logger, "❌ HATA: " + ex.Message);
            }

            return result;
        }

        /// <summary>
        /// Belirtilen bir klasördeki tüm dosyaları recursive tarar ve SHA-256'larını otomatik veritabanına ekler.
        /// </summary>
        public FolderCrawlResult CrawlFolderAndHash(string folderPath, string threatLabel, Action<string> logger = null)
        {
            var res = new FolderCrawlResult();
            if (!Directory.Exists(folderPath))
            {
                res.Message = "Klasör bulunamadı: " + folderPath;
                return res;
            }

            try
            {
                Log(logger, "Klasör taranıyor: " + folderPath);
                string[] files = Directory.GetFiles(folderPath, "*.*", SearchOption.AllDirectories);
                res.TotalFilesScanned = files.Length;

                foreach (var file in files)
                {
                    try
                    {
                        string sha = AntivirusCore.AntivirusEngine.ComputeSha256(file);
                        string fileName = Path.GetFileName(file);
                        string label = string.IsNullOrEmpty(threatLabel) ? ("Suspicious." + fileName) : threatLabel;

                        string existing;
                        if (!_db.CheckHash(sha, out existing))
                        {
                            _db.Add(sha, label);
                            res.AddedSignatures++;
                        }
                        else
                        {
                            res.AlreadyExisting++;
                        }
                    }
                    catch (Exception ex)
                    {
                        res.ErrorsCount++;
                        Log(logger, "Atlandı (" + Path.GetFileName(file) + "): " + ex.Message);
                    }
                }

                res.Success = true;
                res.Message = string.Format("Klasör taraması bitti: {0:N0} dosya tarandı, {1:N0} yeni imza veritabanına eklendi.", res.TotalFilesScanned, res.AddedSignatures);
                Log(logger, "✅ " + res.Message);
            }
            catch (Exception ex)
            {
                res.Success = false;
                res.Message = "Tarama hatası: " + ex.Message;
                Log(logger, "❌ HATA: " + ex.Message);
            }

            return res;
        }

        private void Log(Action<string> logger, string msg)
        {
            if (logger != null)
            {
                logger(string.Format("[{0}] {1}", DateTime.Now.ToString("HH:mm:ss"), msg));
            }
        }
    }

    public class FeedFetchResult
    {
        public bool Success { get; set; }
        public int TotalFetchedLines { get; set; }
        public int AddedNewSignatures { get; set; }
        public int AlreadyExisting { get; set; }
        public string Message { get; set; }
    }

    public class FolderCrawlResult
    {
        public bool Success { get; set; }
        public int TotalFilesScanned { get; set; }
        public int AddedSignatures { get; set; }
        public int AlreadyExisting { get; set; }
        public int ErrorsCount { get; set; }
        public string Message { get; set; }
    }
}
