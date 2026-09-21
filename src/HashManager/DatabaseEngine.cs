using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace AntivirusHashManager
{
    /// <summary>
    /// 1 Milyon+ Hash kapasitesine uygun, bellek ve streaming I/O optimizasyonlu imza motoru.
    /// </summary>
    public class DatabaseEngine
    {
        // Ana sözlük (Hash -> Zararlı Adı): O(1) arama ve mükerrer engelleme
        private readonly Dictionary<string, string> _signatures = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        
        // VirtualMode ListView için hızlı indekslenebilir anahtar listesi
        private readonly List<string> _keys = new List<string>();
        
        // Arama/Filtreleme durumunda gösterilen anahtarlar
        private readonly List<string> _filteredKeys = new List<string>();
        private bool _isFiltered = false;

        private readonly object _lockObj = new object();

        public int Count
        {
            get
            {
                lock (_lockObj)
                {
                    return _signatures.Count;
                }
            }
        }

        public int VisibleCount
        {
            get
            {
                lock (_lockObj)
                {
                    return _isFiltered ? _filteredKeys.Count : _keys.Count;
                }
            }
        }

        public string GetHashAt(int index)
        {
            lock (_lockObj)
            {
                var list = _isFiltered ? _filteredKeys : _keys;
                if (index >= 0 && index < list.Count)
                {
                    return list[index];
                }
                return string.Empty;
            }
        }

        public string GetThreatAt(int index)
        {
            lock (_lockObj)
            {
                string hash = GetHashAt(index);
                if (!string.IsNullOrEmpty(hash) && _signatures.ContainsKey(hash))
                {
                    return _signatures[hash];
                }
                return string.Empty;
            }
        }

        public bool Add(string hash, string threatName)
        {
            if (string.IsNullOrWhiteSpace(hash)) return false;
            hash = CleanHash(hash);
            if (string.IsNullOrEmpty(hash)) return false;

            // Geçersiz uzunluk ya da "bilinen-temiz/dejenere" hash (boş dosya vb.) veritabanına
            // ASLA girmez - istemci bunu her boş dosyada "zararlı" sanıp toplu karantina yapardı.
            if (!IsAcceptableHash(hash)) return false;

            if (string.IsNullOrWhiteSpace(threatName))
                threatName = "Generic.Malware";

            lock (_lockObj)
            {
                if (!_signatures.ContainsKey(hash))
                {
                    _signatures[hash] = threatName.Trim();
                    _keys.Add(hash);
                    if (_isFiltered)
                        _filteredKeys.Add(hash);
                    return true;
                }
                else
                {
                    // Varsa adını güncelle
                    _signatures[hash] = threatName.Trim();
                    return false;
                }
            }
        }

        public bool Remove(string hash)
        {
            if (string.IsNullOrWhiteSpace(hash)) return false;
            hash = CleanHash(hash);

            lock (_lockObj)
            {
                if (_signatures.Remove(hash))
                {
                    _keys.Remove(hash);
                    if (_isFiltered)
                        _filteredKeys.Remove(hash);
                    return true;
                }
            }
            return false;
        }

        public void Clear()
        {
            lock (_lockObj)
            {
                _signatures.Clear();
                _keys.Clear();
                _filteredKeys.Clear();
                _isFiltered = false;
            }
        }

        public bool CheckHash(string hash, out string threatName)
        {
            threatName = null;
            if (string.IsNullOrWhiteSpace(hash)) return false;
            hash = CleanHash(hash);

            lock (_lockObj)
            {
                return _signatures.TryGetValue(hash, out threatName);
            }
        }

        public void ApplyFilter(string query)
        {
            lock (_lockObj)
            {
                if (string.IsNullOrWhiteSpace(query))
                {
                    _isFiltered = false;
                    _filteredKeys.Clear();
                    return;
                }

                _isFiltered = true;
                _filteredKeys.Clear();
                query = query.Trim();

                for (int i = 0; i < _keys.Count; i++)
                {
                    string h = _keys[i];
                    string name = _signatures[h];
                    if (h.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        name.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        _filteredKeys.Add(h);
                    }
                }
            }
        }

        /// <summary>
        /// Toplu TXT dosyasından yüksek hızda hash yükler (1M satır için optimize streaming).
        /// Formatlar: 
        /// 1) hash
        /// 2) hash,zararli_adi
        /// 3) hash:zararli_adi
        /// 4) hash\tzararli_adi
        /// </summary>
        public BulkResult ImportFromTxt(string filePath, Action<int> progressCallback = null)
        {
            var result = new BulkResult();
            if (!File.Exists(filePath)) return result;

            var newHashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
            using (var reader = new StreamReader(fs, Encoding.UTF8))
            {
                string line;
                int processed = 0;
                while ((line = reader.ReadLine()) != null)
                {
                    processed++;
                    line = line.Trim();
                    if (line.Length == 0 || line.StartsWith("#") || line.StartsWith("//"))
                        continue;

                    string hash = null;
                    string name = "Generic.Malware";

                    char[] seps = new char[] { ',', ':', '\t', ';' };
                    int sepIdx = line.IndexOfAny(seps);
                    if (sepIdx > 0)
                    {
                        hash = line.Substring(0, sepIdx).Trim();
                        string rawName = line.Substring(sepIdx + 1).Trim();
                        if (!string.IsNullOrEmpty(rawName))
                            name = rawName;
                    }
                    else
                    {
                        // Boşlukla ayrılmış olabilir
                        int spaceIdx = line.IndexOf(' ');
                        if (spaceIdx > 0)
                        {
                            hash = line.Substring(0, spaceIdx).Trim();
                            string rawName = line.Substring(spaceIdx + 1).Trim();
                            if (!string.IsNullOrEmpty(rawName))
                                name = rawName;
                        }
                        else
                        {
                            hash = line;
                        }
                    }

                    hash = CleanHash(hash);
                    if (IsAcceptableHash(hash))
                    {
                        if (!newHashes.ContainsKey(hash))
                        {
                            newHashes[hash] = name;
                        }
                        else
                        {
                            result.DuplicatesInFile++;
                        }
                    }
                    else
                    {
                        result.InvalidCount++;
                    }

                    if (progressCallback != null && (processed % 25000 == 0))
                    {
                        progressCallback(processed);
                    }
                }
                result.TotalLines = processed;
            }

            // Ana belleğe topluca aktarma
            lock (_lockObj)
            {
                foreach (var kv in newHashes)
                {
                    if (!_signatures.ContainsKey(kv.Key))
                    {
                        _signatures[kv.Key] = kv.Value;
                        _keys.Add(kv.Key);
                        result.AddedCount++;
                    }
                    else
                    {
                        result.ExistingUpdatedCount++;
                    }
                }
                if (_isFiltered)
                {
                    ApplyFilter(string.Empty);
                }
            }

            return result;
        }

        /// <summary>
        /// database.json dosyasını streaming şekilde parse eder (büyük boyutlarda bile çökmez).
        /// </summary>
        public BulkResult LoadFromJson(string filePath)
        {
            var result = new BulkResult();
            if (!File.Exists(filePath)) return result;

            lock (_lockObj)
            {
                _signatures.Clear();
                _keys.Clear();
                _filteredKeys.Clear();
                _isFiltered = false;

                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
                using (var reader = new StreamReader(fs, Encoding.UTF8))
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
                            if (line.StartsWith("}") && !line.Contains(":"))
                            {
                                inSignatures = false;
                                break;
                            }

                            // Örnek: "e3b0c442...": "Test.EICAR",
                            int colonIdx = line.IndexOf(':');
                            if (colonIdx > 0)
                            {
                                string keyPart = line.Substring(0, colonIdx).Trim().Trim('"', ' ');
                                string valPart = line.Substring(colonIdx + 1).Trim().TrimEnd(',').Trim().Trim('"', ' ');

                                keyPart = CleanHash(keyPart);
                                // Bozuk/temiz hash'ler yüklenirken de temizlenir: mevcut database.json'daki
                                // hatalı girdiler bir sonraki yayında buluttan da düşer.
                                if (!string.IsNullOrEmpty(keyPart) && IsAcceptableHash(keyPart))
                                {
                                    _signatures[keyPart] = valPart;
                                    _keys.Add(keyPart);
                                    result.AddedCount++;
                                }
                            }
                        }
                    }
                }
            }

            return result;
        }

        /// <summary>
        /// 1M kaydı GitHub Pages ve antivirüs istemcileri için optimize edilmiş JSON formatında kaydeder.
        /// Otomatik .bak yedeği oluşturur.
        /// </summary>
        public void ExportToJson(string filePath)
        {
            lock (_lockObj)
            {
                // Önceki dosyanın güvenli yedeğini al
                try
                {
                    if (File.Exists(filePath))
                    {
                        string bakPath = filePath + ".bak";
                        File.Copy(filePath, bakPath, true);
                    }
                }
                catch { }

                using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 65536))
                using (var writer = new StreamWriter(fs, Encoding.UTF8))
                {
                    writer.WriteLine("{");
                    writer.WriteLine("  \"schema_version\": \"1.0\",");
                    writer.WriteLine("  \"database_name\": \"Antivirus Signature Database\",");
                    writer.WriteLine("  \"updated_at\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
                    writer.WriteLine("  \"total_signatures\": " + _signatures.Count + ",");
                    writer.WriteLine("  \"hash_type\": \"SHA256/MD5\",");
                    writer.WriteLine("  \"signatures\": {");

                    int count = 0;
                    int total = _signatures.Count;
                    foreach (var kv in _signatures)
                    {
                        count++;
                        string comma = (count < total) ? "," : "";
                        writer.WriteLine("    \"" + kv.Key + "\": \"" + EscapeJson(kv.Value) + "\"" + comma);
                    }

                    writer.WriteLine("  }");
                    writer.WriteLine("}");
                }
            }
        }

        public void ExportToTxt(string filePath)
        {
            lock (_lockObj)
            {
                using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 65536))
                using (var writer = new StreamWriter(fs, Encoding.UTF8))
                {
                    writer.WriteLine("# Samet-AV Signature Export - " + DateTime.Now.ToString());
                    writer.WriteLine("# Format: HASH,MALWARE_NAME");
                    foreach (var kv in _signatures)
                    {
                        writer.WriteLine(kv.Key + "," + kv.Value);
                    }
                }
            }
        }

        private static string CleanHash(string input)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;
            var sb = new StringBuilder(input.Length);
            for (int i = 0; i < input.Length; i++)
            {
                char c = input[i];
                if ((c >= '0' && c <= '9') ||
                    (c >= 'a' && c <= 'f') ||
                    (c >= 'A' && c <= 'F'))
                {
                    sb.Append(char.ToLowerInvariant(c));
                }
            }
            return sb.ToString();
        }

        private static bool IsValidHashLength(string hash)
        {
            if (hash == null) return false;
            int len = hash.Length;
            return len == 32 || len == 40 || len == 64; // MD5, SHA1, SHA256
        }

        // Asla zararlı olamayacak/dejenere hash'ler: boş girdinin MD5/SHA1/SHA256 özeti ve
        // hep-0 / hep-f dizileri. (Gerçek olay: SHA-256("") "Malware.PufaAv.Generic" olarak
        // veritabanına girdi -> istemci her 0 baytlık dosyayı zararlı sanıp yüzlerce sistem
        // dosyasını karantinaya aldı.) Değerleri gözle değil sha256sum ile doğrula.
        private static readonly HashSet<string> RejectedHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA-256("")
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",                         // SHA-1("")
            "d41d8cd98f00b204e9800998ecf8427e",                                 // MD5("")
        };

        public static bool IsAcceptableHash(string hash)
        {
            if (!IsValidHashLength(hash)) return false;
            if (RejectedHashes.Contains(hash)) return false;
            char first = hash[0];
            bool allSame = true;
            for (int i = 1; i < hash.Length; i++)
            {
                if (hash[i] != first) { allSame = false; break; }
            }
            return !allSame; // 000...0 / fff...f gibi dejenere diziler
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return string.Empty;
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
        }
    }

    public class BulkResult
    {
        public int TotalLines { get; set; }
        public int AddedCount { get; set; }
        public int ExistingUpdatedCount { get; set; }
        public int DuplicatesInFile { get; set; }
        public int InvalidCount { get; set; }
    }
}