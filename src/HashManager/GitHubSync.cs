using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace AntivirusHashManager
{
    /// <summary>
    /// GitHub Pages senkronizasyon motoru.
    /// Hem Git CLI (yerel repo varsa) hem de GitHub Git Data API (Tree/Commit/Ref) destekler.
    /// 1MB Contents API sınırını aşar ve 100MB'a kadar database.json ile webdatabase.json dosyalarını
    /// tek bir atomik commit ile buluta yükler.
    /// </summary>
    public class GitHubSync
    {
        public string RepoFullName { get; set; } // Örn: "Samettr08/Samettr08.github.io"
        public string Branch { get; set; }       // Örn: "main"
        public string FilePath { get; set; }     // Geriye dönük uyumluluk için "database.json"
        public string Token { get; set; }        // GitHub Personal Access Token (PAT)

        public GitHubSync()
        {
            RepoFullName = "Samettr08/Samettr08.github.io";
            Branch = "main";
            FilePath = "database.json";
        }

        public SyncResult PushDatabase(string localJsonPath, Action<string> logger = null)
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string webDbPath = Path.Combine(baseDir, "webdatabase.json");
            return PushAllDatabases(localJsonPath, webDbPath, logger);
        }

        public SyncResult PushAllDatabases(string hashDbPath, string webDbPath, Action<string> logger = null)
        {
            var result = new SyncResult();

            if (string.IsNullOrWhiteSpace(Token))
            {
                result.Success = false;
                result.Message = "GitHub Personal Access Token (PAT) girilmedi!";
                return result;
            }

            if (string.IsNullOrWhiteSpace(RepoFullName) || !RepoFullName.Contains("/"))
            {
                result.Success = false;
                result.Message = "Geçersiz Repository formatı! Örn: Samettr08/Samettr08.github.io";
                return result;
            }

            // Yayın öncesi güvenlik kontrolü: hatalı bir veritabanı TÜM istemcilere ulaşır.
            string guardReason = PublishGuard.Check(hashDbPath, webDbPath);
            if (guardReason != null)
            {
                result.Success = false;
                result.Message = "YAYIN DURDURULDU (güvenlik kontrolü): " + guardReason;
                Log(logger, result.Message);
                return result;
            }

            // 1. Öncelik: Yerel .git klasörü ve git.exe varsa yerel Git CLI ile pushla
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            string gitDir = Path.Combine(baseDir, ".git");

            if (Directory.Exists(gitDir))
            {
                Log(logger, "Yerel .git deposu tespit edildi. Git CLI motoru deneniyor...");
                var cliResult = PushViaGitCli(baseDir, hashDbPath, webDbPath, logger);
                if (cliResult.Success)
                {
                    return cliResult;
                }
                Log(logger, "Git CLI ile aktarılamadı (" + cliResult.Message + "). GitHub Git Data REST API deneniyor...");
            }

            // 2. Öncelik veya Yedek: Git Data API (Tree/Commit/Ref) - Bağımsız ve 100MB'a kadar destekler
            return PushViaGitDataApi(hashDbPath, webDbPath, logger);
        }

        #region Git CLI Motoru (Ultra Hızlı ve Büyük Dosyaları Sorunsuz İşler)

        private SyncResult PushViaGitCli(string workingDir, string hashDbPath, string webDbPath, Action<string> logger)
        {
            var result = new SyncResult();
            try
            {
                // Dosyaları stage'e ekle
                List<string> relFiles = new List<string>();
                if (File.Exists(hashDbPath))
                {
                    string f = Path.GetFileName(hashDbPath);
                    relFiles.Add(f);
                }
                if (File.Exists(webDbPath))
                {
                    string f = Path.GetFileName(webDbPath);
                    relFiles.Add(f);
                }

                if (relFiles.Count == 0)
                {
                    result.Success = false;
                    result.Message = "Yüklenecek veritabanı dosyaları bulunamadı.";
                    return result;
                }

                string addArgs = "add " + string.Join(" ", relFiles.ToArray());
                Log(logger, "Git add çalıştırılıyor: " + addArgs);
                RunGitCommand(workingDir, addArgs, 15000);

                // Commit oluştur
                string commitMsg = string.Format("Update threat database (signatures & web domains) [{0}]", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"));
                Log(logger, "Git commit oluşturuluyor...");
                string commitOut = RunGitCommand(workingDir, "commit -m \"" + commitMsg + "\"", 15000);

                if (commitOut.Contains("nothing to commit") || commitOut.Contains("working tree clean"))
                {
                    Log(logger, "Veritabanında değişiklik yok, commit atlandı.");
                }

                // Pushla (Token ile kimlik doğrulamalı URL kullan)
                string branch = string.IsNullOrEmpty(Branch) ? "main" : Branch.Trim();
                string remoteUrl = string.Format("https://{0}@github.com/{1}.git", Token.Trim(), RepoFullName.Trim());

                Log(logger, string.Format("Git push gönderiliyor ({0} -> {1})...", RepoFullName, branch));
                string pushOut = RunGitCommand(workingDir, string.Format("push \"{0}\" {1}", remoteUrl, branch), 60000);

                Log(logger, "Git push tamamlandı: " + pushOut);
                result.Success = true;
                result.Message = "Tebrikler! Hem database.json hem de webdatabase.json başarıyla GitHub Pages'e yüklendi!\nBulut veritabanı birkaç saniye içinde canlıya alınacaktır.";
                return result;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Message = "Git CLI Hatası: " + ex.Message;
                return result;
            }
        }

        private string RunGitCommand(string workingDir, string arguments, int timeoutMs)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "git",
                Arguments = arguments,
                WorkingDirectory = workingDir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (var proc = Process.Start(psi))
            {
                string output = proc.StandardOutput.ReadToEnd();
                string error = proc.StandardError.ReadToEnd();
                if (!proc.WaitForExit(timeoutMs))
                {
                    try { proc.Kill(); } catch { }
                    throw new Exception("Git komutu zaman aşımına uğradı (" + arguments + ")");
                }

                if (proc.ExitCode != 0 && !output.Contains("nothing to commit") && !error.Contains("up-to-date"))
                {
                    string errCombined = (output + " " + error).Trim();
                    if (!string.IsNullOrEmpty(errCombined))
                        throw new Exception(errCombined);
                }

                return output + " " + error;
            }
        }

        #endregion

        #region GitHub Git Data API (Tree / Commit / Ref Motoru - 100MB Destekli)

        private SyncResult PushViaGitDataApi(string hashDbPath, string webDbPath, Action<string> logger)
        {
            var result = new SyncResult();
            try
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; // TLS 1.2

                string repo = RepoFullName.Trim();
                string branch = string.IsNullOrEmpty(Branch) ? "main" : Branch.Trim();

                Log(logger, "GitHub Git Data API başlatılıyor: " + repo + " (" + branch + ")...");

                // 1. Blobları oluştur (100MB'a kadar dosyaları kabul eder)
                var treeEntries = new List<string>();

                if (File.Exists(hashDbPath))
                {
                    Log(logger, "database.json blob nesnesi oluşturuluyor...");
                    string blobSha = CreateBlob(repo, hashDbPath, logger);
                    treeEntries.Add(string.Format("{{\"path\":\"database.json\",\"mode\":\"100644\",\"type\":\"blob\",\"sha\":\"{0}\"}}", blobSha));
                }

                if (File.Exists(webDbPath))
                {
                    Log(logger, "webdatabase.json blob nesnesi oluşturuluyor...");
                    string blobSha = CreateBlob(repo, webDbPath, logger);
                    treeEntries.Add(string.Format("{{\"path\":\"webdatabase.json\",\"mode\":\"100644\",\"type\":\"blob\",\"sha\":\"{0}\"}}", blobSha));
                }

                if (treeEntries.Count == 0)
                {
                    result.Success = false;
                    result.Message = "Yüklenecek dosya bulunamadı!";
                    return result;
                }

                // 2. Branch'in son commit SHA'sını al
                Log(logger, "Branch'in güncel commit referansı alınıyor...");
                string refUrl = string.Format("https://api.github.com/repos/{0}/git/ref/heads/{1}", repo, branch);
                string refJson = SendHttpRequest(refUrl, "GET", null);
                string currentCommitSha = ExtractJsonValue(refJson, "\"sha\"");

                if (string.IsNullOrEmpty(currentCommitSha))
                {
                    throw new Exception("Branch commit SHA alınamadı: " + refJson);
                }
                Log(logger, "Mevcut commit: " + currentCommitSha.Substring(0, Math.Min(10, currentCommitSha.Length)));

                // 3. Commit'in tree SHA'sını al
                string commitUrl = string.Format("https://api.github.com/repos/{0}/git/commits/{1}", repo, currentCommitSha);
                string commitJson = SendHttpRequest(commitUrl, "GET", null);
                string baseTreeSha = ExtractNestedJsonValue(commitJson, "\"tree\"", "\"sha\"");

                if (string.IsNullOrEmpty(baseTreeSha))
                {
                    throw new Exception("Base tree SHA alınamadı: " + commitJson);
                }

                // 4. Yeni Tree oluştur
                Log(logger, "Yeni Tree nesnesi oluşturuluyor...");
                string treeUrl = string.Format("https://api.github.com/repos/{0}/git/trees", repo);
                string treeBody = string.Format("{{\"base_tree\":\"{0}\",\"tree\":[{1}]}}",
                    baseTreeSha, string.Join(",", treeEntries.ToArray()));

                string newTreeJson = SendHttpRequest(treeUrl, "POST", treeBody);
                string newTreeSha = ExtractJsonValue(newTreeJson, "\"sha\"");

                if (string.IsNullOrEmpty(newTreeSha))
                {
                    throw new Exception("Yeni Tree SHA alınamadı: " + newTreeJson);
                }

                // 5. Yeni Commit oluştur
                Log(logger, "Yeni Commit nesnesi oluşturuluyor...");
                string createCommitUrl = string.Format("https://api.github.com/repos/{0}/git/commits", repo);
                string commitMsg = string.Format("Update threat database (signatures & web domains) [{0} UTC]", DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss"));
                string createCommitBody = string.Format(
                    "{{\"message\":\"{0}\",\"tree\":\"{1}\",\"parents\":[\"{2}\"]}}",
                    commitMsg, newTreeSha, currentCommitSha);

                string newCommitJson = SendHttpRequest(createCommitUrl, "POST", createCommitBody);
                string newCommitSha = ExtractJsonValue(newCommitJson, "\"sha\"");

                if (string.IsNullOrEmpty(newCommitSha))
                {
                    throw new Exception("Yeni Commit oluşturulamadı: " + newCommitJson);
                }

                // 6. Branch referansını yeni commit'e güncelle (PATCH)
                Log(logger, "Branch referansı güncelleniyor (HEAD -> " + newCommitSha.Substring(0, 10) + ")...");
                string updateRefUrl = string.Format("https://api.github.com/repos/{0}/git/refs/heads/{1}", repo, branch);
                string updateRefBody = string.Format("{{\"sha\":\"{0}\",\"force\":false}}", newCommitSha);

                SendHttpRequest(updateRefUrl, "PATCH", updateRefBody);

                result.Success = true;
                result.Message = "Tebrikler! Hem database.json hem de webdatabase.json başarıyla GitHub Pages'e yüklendi!\nGitHub Actions ve Pages birkaç saniye içinde canlıya geçecektir.";
                Log(logger, "BAŞARILI: Commit " + newCommitSha.Substring(0, 10) + " yayınlandı.");
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

        private string CreateBlob(string repo, string filePath, Action<string> logger)
        {
            byte[] fileBytes = File.ReadAllBytes(filePath);
            string base64 = Convert.ToBase64String(fileBytes);

            string url = string.Format("https://api.github.com/repos/{0}/git/blobs", repo);
            string body = string.Format("{{\"content\":\"{0}\",\"encoding\":\"base64\"}}", base64);

            string responseJson = SendHttpRequest(url, "POST", body);
            string sha = ExtractJsonValue(responseJson, "\"sha\"");

            if (string.IsNullOrEmpty(sha))
            {
                throw new Exception("Blob oluşturulamadı: " + responseJson);
            }

            Log(logger, string.Format("Blob oluşturuldu: {0} ({1:N0} byte) -> SHA: {2}...",
                Path.GetFileName(filePath), fileBytes.Length, sha.Substring(0, Math.Min(10, sha.Length))));

            return sha;
        }

        private string SendHttpRequest(string url, string method, string jsonBody)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = method;
            req.UserAgent = "Samet-AV-Cloud-Studio/2.0";
            req.Headers.Add("Authorization", "token " + Token.Trim());
            req.Headers.Add("Accept", "application/vnd.github.v3+json");
            req.ContentType = "application/json; charset=utf-8";

            if (!string.IsNullOrEmpty(jsonBody))
            {
                byte[] bytes = Encoding.UTF8.GetBytes(jsonBody);
                req.ContentLength = bytes.Length;
                using (var st = req.GetRequestStream())
                {
                    st.Write(bytes, 0, bytes.Length);
                }
            }

            using (var resp = (HttpWebResponse)req.GetResponse())
            using (var stream = resp.GetResponseStream())
            using (var reader = new StreamReader(stream, Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }

        private static string ExtractJsonValue(string json, string keyWithQuotes)
        {
            var match = Regex.Match(json, keyWithQuotes + "\\s*:\\s*\"([^\"]+)\"");
            if (match.Success) return match.Groups[1].Value;
            return null;
        }

        private static string ExtractNestedJsonValue(string json, string parentKey, string childKey)
        {
            var parentMatch = Regex.Match(json, parentKey + "\\s*:\\s*\\{([^}]+)\\}");
            if (parentMatch.Success)
            {
                return ExtractJsonValue(parentMatch.Groups[1].Value, childKey);
            }
            return null;
        }

        #endregion

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