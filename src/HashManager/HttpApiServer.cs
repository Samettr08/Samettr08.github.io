using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace AntivirusHashManager
{
    /// <summary>
    /// Sıfır yönetici izni gerektiren, saf TcpListener tabanlı yüksek hızlı Micro-REST HTTP API Sunucusu.
    /// URL: http://127.0.0.1:8765/
    /// PufaAv (C/C++), Python, cURL vb. tüm istemciler hem Hash hem de Zararlı URL sorgulayabilir.
    /// </summary>
    public class HttpApiServer
    {
        private TcpListener _tcpListener;
        private readonly DatabaseEngine _db;
        private readonly WebDatabaseEngine _webDb;
        private readonly Action _onDataModified;
        private Thread _serverThread;
        private volatile bool _isRunning = false;
        public int Port { get; private set; }

        public event Action<string> OnLog;

        public HttpApiServer(DatabaseEngine db, WebDatabaseEngine webDb, Action onDataModified, int port = 8765)
        {
            _db = db;
            _webDb = webDb;
            _onDataModified = onDataModified;
            Port = port;
        }

        public HttpApiServer(DatabaseEngine db, Action onDataModified, int port = 8765)
            : this(db, null, onDataModified, port)
        {
        }

        public void Start()
        {
            if (_isRunning) return;

            try
            {
                _tcpListener = new TcpListener(IPAddress.Loopback, Port);
                _tcpListener.Start();

                _isRunning = true;
                _serverThread = new Thread(ListenLoop)
                {
                    IsBackground = true,
                    Name = "TcpHttpApiServerThread"
                };
                _serverThread.Start();

                Log("Yerel HTTP API Sunucusu Aktif: http://127.0.0.1:" + Port + "/");
            }
            catch (Exception ex)
            {
                Log("HTTP API başlatılamadı: " + ex.Message);
            }
        }

        public void Stop()
        {
            _isRunning = false;
            try
            {
                if (_tcpListener != null)
                {
                    _tcpListener.Stop();
                }
            }
            catch { }
        }

        private void ListenLoop()
        {
            while (_isRunning)
            {
                try
                {
                    var client = _tcpListener.AcceptTcpClient();
                    ThreadPool.QueueUserWorkItem(ProcessClient, client);
                }
                catch
                {
                    if (!_isRunning) break;
                }
            }
        }

        private void ProcessClient(object state)
        {
            var client = (TcpClient)state;
            try
            {
                using (client)
                using (var stream = client.GetStream())
                using (var reader = new StreamReader(stream, Encoding.UTF8))
                {
                    string requestLine = reader.ReadLine();
                    if (string.IsNullOrEmpty(requestLine)) return;

                    string[] parts = requestLine.Split(' ');
                    if (parts.Length < 2) return;

                    string fullUrl = parts[1];
                    string path = fullUrl;
                    string query = string.Empty;

                    int qIdx = fullUrl.IndexOf('?');
                    if (qIdx >= 0)
                    {
                        path = fullUrl.Substring(0, qIdx);
                        query = fullUrl.Substring(qIdx + 1);
                    }

                    path = path.ToLowerInvariant();
                    string jsonResponse = "{}";
                    int statusCode = 200;

                    if (path == "/check")
                    {
                        string hash = GetQueryParam(query, "hash");
                        string threatName;
                        bool isThreat = _db.CheckHash(hash, out threatName);

                        jsonResponse = string.Format(
                            "{{\"hash\":\"{0}\",\"is_threat\":{1},\"threat_name\":\"{2}\",\"database_count\":{3}}}",
                            EscapeJson(hash),
                            isThreat ? "true" : "false",
                            EscapeJson(threatName ?? string.Empty),
                            _db.Count
                        );

                        Log(string.Format("HTTP /check -> {0} -> {1}", 
                            hash.Length > 16 ? hash.Substring(0, 16) + "..." : hash,
                            isThreat ? ("🚨 " + threatName) : "✅ TEMİZ"));
                    }
                    else if (path == "/check_url")
                    {
                        string url = GetQueryParam(query, "url");
                        string normDomain = WebDatabaseEngine.NormalizeDomain(url);
                        WebBlockRule rule = null;
                        bool isBlocked = _webDb != null && _webDb.IsBlocked(url, out rule);

                        jsonResponse = string.Format(
                            "{{\"url\":\"{0}\",\"domain\":\"{1}\",\"is_blocked\":{2},\"category\":\"{3}\",\"matched_rule\":\"{4}\",\"total_domains\":{5}}}",
                            EscapeJson(url),
                            EscapeJson(normDomain),
                            isBlocked ? "true" : "false",
                            EscapeJson(rule != null ? rule.Category : string.Empty),
                            EscapeJson(rule != null ? rule.Domain : string.Empty),
                            _webDb != null ? _webDb.Count : 0
                        );

                        Log(string.Format("HTTP /check_url -> {0} ({1}) -> {2}",
                            url, normDomain,
                            isBlocked ? ("🚨 ENGELLENDİ: " + rule.Category) : "✅ GÜVENLİ"));
                    }
                    else if (path == "/add")
                    {
                        string hash = GetQueryParam(query, "hash");
                        string name = GetQueryParam(query, "name");
                        if (string.IsNullOrEmpty(name)) name = "Client.Detected";

                        bool added = _db.Add(hash, name);
                        if (_onDataModified != null) _onDataModified();

                        jsonResponse = string.Format("{{\"status\":\"OK\",\"added\":{0},\"hash\":\"{1}\",\"database_count\":{2}}}",
                            added ? "true" : "false", EscapeJson(hash), _db.Count);

                        Log("HTTP /add -> " + hash);
                    }
                    else if (path == "/add_url")
                    {
                        string url = GetQueryParam(query, "url");
                        string cat = GetQueryParam(query, "category");
                        if (string.IsNullOrEmpty(cat)) cat = "Malware Distribution";

                        bool added = _webDb != null && _webDb.AddRule(url, cat);
                        if (_onDataModified != null) _onDataModified();

                        jsonResponse = string.Format("{{\"status\":\"OK\",\"added\":{0},\"url\":\"{1}\",\"total_domains\":{2}}}",
                            added ? "true" : "false", EscapeJson(url), _webDb != null ? _webDb.Count : 0);

                        Log("HTTP /add_url -> " + url);
                    }
                    else if (path == "/stats")
                    {
                        jsonResponse = string.Format(
                            "{{\"status\":\"ONLINE\",\"version\":\"2.0\",\"signatures_count\":{0},\"domains_count\":{1}}}",
                            _db.Count,
                            _webDb != null ? _webDb.Count : 0);
                    }
                    else
                    {
                        statusCode = 404;
                        jsonResponse = "{\"error\":\"Endpoint not found. Use /check?hash=..., /check_url?url=..., /add?hash=..., /add_url?url=..., or /stats\"}";
                    }

                    byte[] bodyBytes = Encoding.UTF8.GetBytes(jsonResponse);
                    string statusText = (statusCode == 200) ? "200 OK" : "404 Not Found";

                    string header = string.Format(
                        "HTTP/1.1 {0}\r\n" +
                        "Content-Type: application/json; charset=utf-8\r\n" +
                        "Access-Control-Allow-Origin: *\r\n" +
                        "Content-Length: {1}\r\n" +
                        "Connection: close\r\n\r\n",
                        statusText,
                        bodyBytes.Length
                    );

                    byte[] headerBytes = Encoding.ASCII.GetBytes(header);
                    stream.Write(headerBytes, 0, headerBytes.Length);
                    stream.Write(bodyBytes, 0, bodyBytes.Length);
                    stream.Flush();
                }
            }
            catch { }
        }

        private string GetQueryParam(string query, string key)
        {
            if (string.IsNullOrEmpty(query)) return string.Empty;
            string[] pairs = query.Split('&');
            foreach (var pair in pairs)
            {
                int eq = pair.IndexOf('=');
                if (eq > 0)
                {
                    string k = pair.Substring(0, eq).Trim();
                    string v = pair.Substring(eq + 1).Trim();
                    if (k.Equals(key, StringComparison.OrdinalIgnoreCase))
                    {
                        return Uri.UnescapeDataString(v);
                    }
                }
            }
            return string.Empty;
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return string.Empty;
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
        }

        private void Log(string msg)
        {
            var handler = OnLog;
            if (handler != null)
            {
                handler(string.Format("[{0}] {1}", DateTime.Now.ToString("HH:mm:ss.fff"), msg));
            }
        }
    }
}
