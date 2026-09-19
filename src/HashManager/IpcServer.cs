using System;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Threading;

namespace AntivirusHashManager
{
    /// <summary>
    /// Antivirüs EXE'leriniz arasında milisaniyenin altında iletişim sağlayan Named Pipe Sunucusu.
    /// Scanner.exe, WebGuard.exe veya Guard.exe gibi diğer programlar buraya bağlanıp anında hash veya URL sorgular.
    /// Pipe Yolu: \\.\pipe\AntivirusHashPipe
    /// </summary>
    public class IpcServer
    {
        public const string PIPE_NAME = "AntivirusHashPipe";
        private readonly DatabaseEngine _db;
        private readonly WebDatabaseEngine _webDb;
        private Thread _listenThread;
        private volatile bool _isRunning = false;

        public event Action<string> OnLog;
        public bool IsRunning { get { return _isRunning; } }

        public IpcServer(DatabaseEngine db, WebDatabaseEngine webDb = null)
        {
            _db = db;
            _webDb = webDb;
        }

        public void Start()
        {
            if (_isRunning) return;
            _isRunning = true;
            _listenThread = new Thread(ListenLoop);
            _listenThread.IsBackground = true;
            _listenThread.Name = "AntivirusIpcServerThread";
            _listenThread.Start();
            Log("IPC Sunucusu başlatıldı: \\\\.\\pipe\\" + PIPE_NAME);
        }

        public void Stop()
        {
            _isRunning = false;
            try
            {
                // Kendine bir dummy ping atarak pipe bloğunu çöz
                using (var client = new NamedPipeClientStream(".", PIPE_NAME, PipeDirection.InOut))
                {
                    client.Connect(100);
                }
            }
            catch { }
            Log("IPC Sunucusu durduruldu.");
        }

        private void ListenLoop()
        {
            while (_isRunning)
            {
                try
                {
                    using (var pipeServer = new NamedPipeServerStream(
                        PIPE_NAME,
                        PipeDirection.InOut,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.None))
                    {
                        pipeServer.WaitForConnection();

                        if (!_isRunning) break;

                        using (var reader = new StreamReader(pipeServer, Encoding.UTF8))
                        using (var writer = new StreamWriter(pipeServer, Encoding.UTF8) { AutoFlush = true })
                        {
                            string request = reader.ReadLine();
                            if (!string.IsNullOrEmpty(request))
                            {
                                string response = ProcessCommand(request.Trim());
                                writer.WriteLine(response);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (_isRunning)
                    {
                        Log("IPC Döngü Uyarısı: " + ex.Message);
                        Thread.Sleep(100);
                    }
                }
            }
        }

        private string ProcessCommand(string cmd)
        {
            if (cmd.StartsWith("CHECK:", StringComparison.OrdinalIgnoreCase))
            {
                string hash = cmd.Substring(6).Trim();
                string threatName;
                if (_db.CheckHash(hash, out threatName))
                {
                    Log(string.Format("Hash Sorgu: {0} -> [🚨 ZARARLI: {1}]", Truncate(hash), threatName));
                    return "THREAT:" + threatName;
                }
                else
                {
                    Log(string.Format("Hash Sorgu: {0} -> [✅ TEMİZ]", Truncate(hash)));
                    return "CLEAN";
                }
            }
            else if (cmd.StartsWith("CHECK_URL:", StringComparison.OrdinalIgnoreCase))
            {
                string url = cmd.Substring(10).Trim();
                WebBlockRule rule;
                if (_webDb != null && _webDb.IsBlocked(url, out rule))
                {
                    Log(string.Format("URL Sorgu: {0} -> [🚨 ENGELLENDİ: {1} ({2})]", url, rule.Category, rule.Domain));
                    return "BLOCKED:" + rule.Category + ":" + rule.Domain;
                }
                else
                {
                    Log(string.Format("URL Sorgu: {0} -> [✅ GÜVENLİ]", url));
                    return "CLEAN";
                }
            }
            else if (cmd.Equals("PING", StringComparison.OrdinalIgnoreCase))
            {
                return "PONG";
            }
            else if (cmd.Equals("COUNT", StringComparison.OrdinalIgnoreCase))
            {
                int webCount = _webDb != null ? _webDb.Count : 0;
                return string.Format("COUNT:{0}:{1}", _db.Count, webCount);
            }
            else
            {
                return "ERROR:UnknownCommand";
            }
        }

        private string Truncate(string h)
        {
            if (h.Length > 16)
                return h.Substring(0, 16) + "...";
            return h;
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