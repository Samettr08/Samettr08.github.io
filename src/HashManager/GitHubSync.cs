using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace AntivirusHashManager
{
    /// <summary>
    /// GitHub REST API üzerinden database.json dosyasını samettr08.github.io reposuna doğrudan commit eder.
    /// Harici git kurulumuna veya komut satırına ihtiyaç duymaz!
    /// </summary>
    public class GitHubSync
    {
        public string RepoFullName { get; set; } // Örn: "samettr08/samettr08.github.io"
        public string Branch { get; set; }       // Örn: "main"
        public string FilePath { get; set; }     // Örn: "database.json"
        public string Token { get; set; }        // GitHub Personal Access Token (PAT)

        public GitHubSync()
        {
            RepoFullName = "samettr08/samettr08.github.io";
            Branch = "main";
            FilePath = "database.json";
        }

        public SyncResult PushDatabase(string localJsonPath, Action<string> logger = null)
        {
            var result = new SyncResult();

            if (!File.Exists(localJsonPath))
            {
                result.Success = false;
                result.Message = "Yerel veritabanı dosyası bulunamadı: " + localJsonPath;
                return result;
            }

            if (string.IsNullOrWhiteSpace(Token))
            {
                result.Success = false;
                result.Message = "GitHub Personal Access Token (PAT) girilmedi!";
                return result;
            }

            if (string.IsNullOrWhiteSpace(RepoFullName) || !RepoFullName.Contains("/"))
            {
                result.Success = false;
                result.Message = "Geçersiz Repository formatı! Örn: samettr08/samettr08.github.io";
                return result;
            }

            try
            {
                // Güvenli TLS 1.2 protokolünü zorla
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; // Tls12

                Log(logger, "GitHub API kontrol ediliyor: " + RepoFullName + " (" + Branch + ")...");

                // 1. Adım: Repoda dosya zaten var mı ve SHA'sı ne?
                string apiUrl = string.Format("https://api.github.com/repos/{0}/contents/{1}?ref={2}", 
                    RepoFullName.Trim(), FilePath.Trim(), Branch.Trim());

                string existingSha = GetFileSha(apiUrl, Token, logger);
                if (existingSha != null)
                {
                    Log(logger, "Mevcut dosya bulundu. SHA: " + existingSha.Substring(0, Math.Min(10, existingSha.Length)) + "...");
                }
                else
                {
                    Log(logger, "Dosya repoda henüz yok, yeni oluşturulacak.");
                }

                // 2. Adım: Yerel dosyayı Base64'e dönüştür
                Log(logger, "Yerel veritabanı Base64 formatına çevriliyor...");
                byte[] fileBytes = File.ReadAllBytes(localJsonPath);
                string base64Content = Convert.ToBase64String(fileBytes);
                Log(logger, string.Format("Dosya boyutu: {0:N0} byte (Base64: {1:N0} karakter).", fileBytes.Length, base64Content.Length));

                // 3. Adım: PUT isteği ile GitHub'a yükle
                Log(logger, "GitHub REST API'ye PUT isteği gönderiliyor (Commit yapılıyor)...");

                var putRequest = (HttpWebRequest)WebRequest.Create(apiUrl);
                putRequest.Method = "PUT";
                putRequest.UserAgent = "Samet-AV-Hash-Manager/1.0";
                putRequest.Headers.Add("Authorization", "token " + Token.Trim());
                putRequest.Headers.Add("Accept", "application/vnd.github.v3+json");
                putRequest.ContentType = "application/json; charset=utf-8";

                // JSON gövdesini oluştur
                var sb = new StringBuilder();
                sb.Append("{");
                sb.Append("\"message\":\"Update threat signature database [Samet-AV Studio]\",");
                sb.Append("\"content\":\"" + base64Content + "\",");
                sb.Append("\"branch\":\"" + Branch.Trim() + "\"");
                if (!string.IsNullOrEmpty(existingSha))
                {
                    sb.Append(",\"sha\":\"" + existingSha + "\"");
                }
                sb.Append("}");

                byte[] bodyBytes = Encoding.UTF8.GetBytes(sb.ToString());
                putRequest.ContentLength = bodyBytes.Length;

                using (var reqStream = putRequest.GetRequestStream())
                {
                    reqStream.Write(bodyBytes, 0, bodyBytes.Length);
                }

                using (var response = (HttpWebResponse)putRequest.GetResponse())
                using (var respStream = response.GetResponseStream())
                using (var reader = new StreamReader(respStream, Encoding.UTF8))
                {
                    string respText = reader.ReadToEnd();
                    if (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.Created)
                    {
                        result.Success = true;
                        result.Message = "Tebrikler! database.json başarıyla GitHub Pages'e yüklendi.\nGitHub Actions/Pages birkaç saniye içinde güncellenecektir.";
                        Log(logger, "BAŞARILI: HTTP " + (int)response.StatusCode + " OK.");
                    }
                    else
                    {
                        result.Success = false;
                        result.Message = "Beklenmeyen yanıt: " + response.StatusCode;
                        Log(logger, "Hata yanıtı: " + respText);
                    }
                }
            }
            catch (WebException wex)
            {
                result.Success = false;
                string errDetails = wex.Message;
                if (wex.Response != null)
                {
                    using (var respStream = wex.Response.GetResponseStream())
                    using (var reader = new StreamReader(respStream, Encoding.UTF8))
                    {
                        errDetails = reader.ReadToEnd();
                    }
                }
                result.Message = "GitHub API Hatası: " + errDetails;
                Log(logger, "HATA: " + errDetails);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = "Genel Hata: " + ex.Message;
                Log(logger, "HATA: " + ex.ToString());
            }

            return result;
        }

        private string GetFileSha(string apiUrl, string token, Action<string> logger)
        {
            try
            {
                var request = (HttpWebRequest)WebRequest.Create(apiUrl);
                request.Method = "GET";
                request.UserAgent = "Samet-AV-Hash-Manager/1.0";
                request.Headers.Add("Authorization", "token " + token.Trim());
                request.Headers.Add("Accept", "application/vnd.github.v3+json");

                using (var response = (HttpWebResponse)request.GetResponse())
                using (var stream = response.GetResponseStream())
                using (var reader = new StreamReader(stream, Encoding.UTF8))
                {
                    string json = reader.ReadToEnd();
                    // "sha": "..." regex ile hızlıca yakala
                    var match = Regex.Match(json, "\"sha\"\\s*:\\s*\"([a-f0-9]+)\"");
                    if (match.Success)
                    {
                        return match.Groups[1].Value;
                    }
                }
            }
            catch (WebException ex)
            {
                var httpResp = ex.Response as HttpWebResponse;
                if (httpResp != null && httpResp.StatusCode == HttpStatusCode.NotFound)
                {
                    // Dosya henüz repoda yok, normal
                    return null;
                }
                Log(logger, "SHA alma uyarısı: " + ex.Message);
            }
            return null;
        }

        private void Log(Action<string> logger, string msg)
        {
            if (logger != null)
            {
                logger(string.Format("[{0}] {1}", DateTime.Now.ToString("HH:mm:ss"), msg));
            }
        }
    }

    public class SyncResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
    }
}