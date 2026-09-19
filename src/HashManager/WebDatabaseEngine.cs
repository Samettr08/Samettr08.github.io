using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace AntivirusHashManager
{
    /// <summary>
    /// Zararlı Web Siteleri, Oltalama (Phishing), C2 ve Zararlı Domainlerin yönetildiği,
    /// alt sayfaları ve alt alan adlarını (wildcard) otomatik kapsayan Web Veritabanı Motoru.
    /// </summary>
    public class WebDatabaseEngine
    {
        private readonly Dictionary<string, WebBlockRule> _rules = new Dictionary<string, WebBlockRule>(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> _keys = new List<string>();
        private readonly List<string> _filteredKeys = new List<string>();
        private bool _isFiltered = false;
        private readonly object _lockObj = new object();

        public int Count
        {
            get
            {
                lock (_lockObj)
                {
                    return _rules.Count;
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

        public string GetDomainAt(int index)
        {
            lock (_lockObj)
            {
                var list = _isFiltered ? _filteredKeys : _keys;
                if (index >= 0 && index < list.Count)
                    return list[index];
                return string.Empty;
            }
        }

        public WebBlockRule GetRuleAt(int index)
        {
            lock (_lockObj)
            {
                string domain = GetDomainAt(index);
                if (!string.IsNullOrEmpty(domain) && _rules.ContainsKey(domain))
                    return _rules[domain];
                return null;
            }
        }

        /// <summary>
        /// URL veya Domain'den temiz host kök alan adını çıkarır.
        /// Örn: https://malware.com/sub/page?id=1 -> malware.com
        /// </summary>
        public static string NormalizeDomain(string input)
        {
            if (string.IsNullOrWhiteSpace(input)) return string.Empty;
            string clean = input.Trim().ToLowerInvariant();

            // Protokolü temizle
            if (clean.StartsWith("https://")) clean = clean.Substring(8);
            else if (clean.StartsWith("http://")) clean = clean.Substring(7);

            // Yol ve sorgu parametrelerini temizle
            int slashIdx = clean.IndexOf('/');
            if (slashIdx >= 0) clean = clean.Substring(0, slashIdx);

            int colonIdx = clean.IndexOf(':');
            if (colonIdx >= 0) clean = clean.Substring(0, colonIdx);

            // Başındaki *. temizle
            if (clean.StartsWith("*.")) clean = clean.Substring(2);

            return clean.Trim('.', ' ');
        }

        public bool AddRule(string rawUrlOrDomain, string category = "Malware Distribution")
        {
            string domain = NormalizeDomain(rawUrlOrDomain);
            if (string.IsNullOrEmpty(domain) || !domain.Contains(".")) return false;

            if (string.IsNullOrWhiteSpace(category)) category = "Malware Distribution";

            lock (_lockObj)
            {
                var rule = new WebBlockRule
                {
                    Domain = domain,
                    Category = category.Trim(),
                    Wildcard = true,
                    BlockAllSubpages = true,
                    AddedAt = DateTime.UtcNow.ToString("yyyy-MM-dd")
                };

                if (!_rules.ContainsKey(domain))
                {
                    _rules[domain] = rule;
                    _keys.Add(domain);
                    if (_isFiltered) _filteredKeys.Add(domain);
                    return true;
                }
                else
                {
                    _rules[domain] = rule;
                    return false;
                }
            }
        }

        public bool RemoveRule(string rawUrlOrDomain)
        {
            string domain = NormalizeDomain(rawUrlOrDomain);
            if (string.IsNullOrEmpty(domain)) return false;

            lock (_lockObj)
            {
                if (_rules.Remove(domain))
                {
                    _keys.Remove(domain);
                    if (_isFiltered) _filteredKeys.Remove(domain);
                    return true;
                }
            }
            return false;
        }

        public void Clear()
        {
            lock (_lockObj)
            {
                _rules.Clear();
                _keys.Clear();
                _filteredKeys.Clear();
                _isFiltered = false;
            }
        }

        /// <summary>
        /// Bir URL'nin veya domainin engelli olup olmadığını kontrol eder.
        /// Ana domain engelliyse tüm alt sayfaları ve alt alan adlarını engelli kabul eder!
        /// </summary>
        public bool IsBlocked(string urlOrDomain, out WebBlockRule matchedRule)
        {
            matchedRule = null;
            string host = NormalizeDomain(urlOrDomain);
            if (string.IsNullOrEmpty(host)) return false;

            lock (_lockObj)
            {
                // 1. Tam eşleşme
                if (_rules.TryGetValue(host, out matchedRule))
                    return true;

                // 2. Üst domain eşleşmesi (örn: sub.login.malware.com -> malware.com kuralı engeller)
                string[] parts = host.Split('.');
                for (int i = 1; i < parts.Length - 1; i++)
                {
                    string parent = string.Join(".", parts, i, parts.Length - i);
                    if (_rules.TryGetValue(parent, out matchedRule))
                        return true;
                }
            }

            return false;
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
                    string d = _keys[i];
                    var rule = _rules[d];
                    if (d.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        rule.Category.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        _filteredKeys.Add(d);
                    }
                }
            }
        }

        public BulkDomainResult ImportFromTxt(string filePath)
        {
            var result = new BulkDomainResult();
            if (!File.Exists(filePath)) return result;

            var newRules = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
            using (var reader = new StreamReader(fs, Encoding.UTF8))
            {
                string line;
                int totalLines = 0;
                while ((line = reader.ReadLine()) != null)
                {
                    totalLines++;
                    line = line.Trim();
                    if (line.Length == 0 || line.StartsWith("#") || line.StartsWith("//"))
                        continue;

                    string domain = null;
                    string cat = "Malware Distribution";

                    int commaIdx = line.IndexOf(',');
                    if (commaIdx > 0)
                    {
                        domain = line.Substring(0, commaIdx).Trim();
                        string rawCat = line.Substring(commaIdx + 1).Trim();
                        if (!string.IsNullOrEmpty(rawCat)) cat = rawCat;
                    }
                    else
                    {
                        domain = line;
                    }

                    domain = NormalizeDomain(domain);
                    if (!string.IsNullOrEmpty(domain) && domain.Contains("."))
                    {
                        if (!newRules.ContainsKey(domain))
                            newRules[domain] = cat;
                    }
                    else
                    {
                        result.InvalidCount++;
                    }
                }
                result.TotalLines = totalLines;
            }

            lock (_lockObj)
            {
                foreach (var kv in newRules)
                {
                    if (AddRule(kv.Key, kv.Value))
                        result.AddedCount++;
                    else
                        result.ExistingUpdatedCount++;
                }
            }

            return result;
        }

        public void LoadFromJson(string filePath)
        {
            if (!File.Exists(filePath)) return;

            lock (_lockObj)
            {
                _rules.Clear();
                _keys.Clear();
                _filteredKeys.Clear();
                _isFiltered = false;

                using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
                using (var reader = new StreamReader(fs, Encoding.UTF8))
                {
                    string line;
                    bool inRules = false;
                    while ((line = reader.ReadLine()) != null)
                    {
                        line = line.Trim();
                        if (line.Contains("\"rules\""))
                        {
                            inRules = true;
                            continue;
                        }

                        if (inRules)
                        {
                            if (line.StartsWith("}") && !line.Contains(":"))
                            {
                                inRules = false;
                                break;
                            }

                            // Örn: "0following.com": { "category": "Malware Distribution", ... }
                            int colonIdx = line.IndexOf(':');
                            if (colonIdx > 0)
                            {
                                string domainKey = line.Substring(0, colonIdx).Trim().Trim('"', ' ');
                                domainKey = NormalizeDomain(domainKey);

                                if (!string.IsNullOrEmpty(domainKey) && domainKey.Contains("."))
                                {
                                    string cat = "Malware Distribution";
                                    var match = Regex.Match(line, "\"category\"\\s*:\\s*\"([^\"]+)\"");
                                    if (match.Success) cat = match.Groups[1].Value;

                                    var rule = new WebBlockRule
                                    {
                                        Domain = domainKey,
                                        Category = cat,
                                        Wildcard = true,
                                        BlockAllSubpages = true,
                                        AddedAt = DateTime.UtcNow.ToString("yyyy-MM-dd")
                                    };

                                    if (!_rules.ContainsKey(domainKey))
                                    {
                                        _rules[domainKey] = rule;
                                        _keys.Add(domainKey);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        public void ExportToJson(string filePath)
        {
            lock (_lockObj)
            {
                try
                {
                    if (File.Exists(filePath))
                    {
                        File.Copy(filePath, filePath + ".bak", true);
                    }
                }
                catch { }

                using (var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, 65536))
                using (var writer = new StreamWriter(fs, Encoding.UTF8))
                {
                    writer.WriteLine("{");
                    writer.WriteLine("  \"schema_version\": \"1.0\",");
                    writer.WriteLine("  \"database_name\": \"Samet-AV Malicious Web & Domain Database\",");
                    writer.WriteLine("  \"updated_at\": \"" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ") + "\",");
                    writer.WriteLine("  \"total_domains\": " + _rules.Count + ",");
                    writer.WriteLine("  \"rules\": {");

                    int count = 0;
                    int total = _rules.Count;
                    foreach (var kv in _rules)
                    {
                        count++;
                        string comma = (count < total) ? "," : "";
                        var r = kv.Value;
                        writer.WriteLine(string.Format("    \"{0}\": {{ \"category\": \"{1}\", \"wildcard\": true, \"block_all_subpages\": true, \"added_at\": \"{2}\" }}{3}",
                            EscapeJson(r.Domain), EscapeJson(r.Category), r.AddedAt, comma));
                    }

                    writer.WriteLine("  }");
                    writer.WriteLine("}");
                }
            }
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return string.Empty;
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
        }
    }

    public class WebBlockRule
    {
        public string Domain { get; set; }
        public string Category { get; set; }
        public bool Wildcard { get; set; }
        public bool BlockAllSubpages { get; set; }
        public string AddedAt { get; set; }
    }

    public class BulkDomainResult
    {
        public int TotalLines { get; set; }
        public int AddedCount { get; set; }
        public int ExistingUpdatedCount { get; set; }
        public int InvalidCount { get; set; }
    }
}
