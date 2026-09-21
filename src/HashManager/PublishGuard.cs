using System;
using System.IO;
using System.Text.RegularExpressions;

namespace AntivirusHashManager
{
    /// <summary>
    /// Buluta (GitHub Pages) yayınlamadan ÖNCE veritabanı dosyalarını doğrular. Amaç: hatalı bir
    /// veritabanının, onu her 2 dakikada indiren TÜM antivirüs istemcilerine ulaşmasını önlemek.
    /// (Gerçek olay: SHA-256("") "zararlı" diye yayınlandı, istemciler her boş dosyayı karantinaya aldı.)
    /// </summary>
    public static class PublishGuard
    {
        // Bir önceki sürüme (.bak) göre bu orandan fazla küçülme = büyük olasılıkla kazara silme/bozulma.
        private const double MaxAllowedShrink = 0.20;

        // "Zorla yayınla" bilinçli bir karar olmalı: true yapılırsa küçülme kontrolü atlanır.
        public static bool AllowLargeDrop = false;

        private static readonly string[] BadHashes =
        {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA-256("")
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",                         // SHA-1("")
            "d41d8cd98f00b204e9800998ecf8427e",                                 // MD5("")
        };

        /// <summary>null = yayınlanabilir; aksi halde engelleme nedeni (Türkçe).</summary>
        public static string Check(string hashDbPath, string webDbPath)
        {
            string r = CheckHashDb(hashDbPath);
            if (r != null) return r;
            return CheckWebDb(webDbPath);
        }

        private static string CheckHashDb(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
                return "Hash veritabanı dosyası bulunamadı: " + path;

            string text = File.ReadAllText(path);
            int actual = CountMatches(text, "\"[0-9a-fA-F]{32,64}\"\\s*:");
            int declared = DeclaredCount(text, "total_signatures");

            if (actual == 0) return "database.json içinde hiç imza yok (boş/bozuk dosya).";
            if (declared >= 0 && declared != actual)
                return string.Format("database.json: total_signatures ({0}) gerçek imza sayısıyla ({1}) uyuşmuyor.", declared, actual);

            foreach (string bad in BadHashes)
            {
                if (text.IndexOf("\"" + bad + "\"", StringComparison.OrdinalIgnoreCase) >= 0)
                    return "database.json'da zararlı OLAMAYACAK bir hash var (boş dosya özeti: " + bad + "). Önce silin.";
            }
            if (Regex.IsMatch(text, "\"(0{32,64}|[fF]{32,64})\"\\s*:"))
                return "database.json'da hep-0 / hep-f gibi dejenere bir hash var.";
            // Yanlış uzunlukta (ör. 65 karakter) anahtarlar - istemci sessizce yok sayar ama temiz olmalı.
            if (Regex.IsMatch(text, "\"[0-9a-fA-F]{65,}\"\\s*:"))
                return "database.json'da 64 karakterden uzun (bozuk) bir hash var.";

            return CheckShrink(path, actual, "hash", "\"[0-9a-fA-F]{32,64}\"\\s*:");
        }

        private static string CheckWebDb(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null; // web DB opsiyonel

            string text = File.ReadAllText(path);
            int actual = CountMatches(text, "\"category\"\\s*:");
            int declared = DeclaredCount(text, "total_domains");
            if (actual == 0) return "webdatabase.json içinde hiç kural yok (boş/bozuk dosya).";
            if (declared >= 0 && declared != actual)
                return string.Format("webdatabase.json: total_domains ({0}) gerçek kural sayısıyla ({1}) uyuşmuyor.", declared, actual);

            // Asla engellenmemesi gereken altyapı adları (WebDatabaseEngine.NeverBlock ile aynı fikir).
            string[] never = { "github.io", "github.com", "microsoft.com", "google.com", "windowsupdate.com",
                               "githubusercontent.com", "samettr08.github.io" };
            foreach (string d in never)
            {
                if (text.IndexOf("\"" + d + "\"", StringComparison.OrdinalIgnoreCase) >= 0)
                    return "webdatabase.json'da engellenmemesi gereken altyapı alan adı var: " + d;
            }

            return CheckShrink(path, actual, "web", "\"category\"\\s*:");
        }

        private static string CheckShrink(string path, int actual, string label, string pattern)
        {
            if (AllowLargeDrop) return null;
            string bak = path + ".bak";
            if (!File.Exists(bak)) return null;
            int previous;
            try { previous = CountMatches(File.ReadAllText(bak), pattern); }
            catch { return null; }
            if (previous >= 100 && actual < previous * (1.0 - MaxAllowedShrink))
            {
                return string.Format(
                    "{0} veritabanı bir önceki sürüme göre %{1:0} küçülmüş ({2} -> {3}). Kazara silme/bozulma olabilir; " +
                    "bilerek yaptıysanız .bak dosyasını silip tekrar deneyin.",
                    label, (1.0 - (double)actual / previous) * 100, previous, actual);
            }
            return null;
        }

        private static int CountMatches(string text, string pattern)
        {
            return Regex.Matches(text, pattern).Count;
        }

        private static int DeclaredCount(string text, string key)
        {
            var m = Regex.Match(text, "\"" + key + "\"\\s*:\\s*(\\d+)");
            int v;
            return (m.Success && int.TryParse(m.Groups[1].Value, out v)) ? v : -1;
        }
    }
}
