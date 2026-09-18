using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AntivirusHashManager
{
    public class MainForm : Form
    {
        private readonly DatabaseEngine _db = new DatabaseEngine();
        private readonly GitHubSync _ghSync = new GitHubSync();
        private IpcServer _ipcServer;

        // UI Bileşenleri
        private TabControl tabControl;
        private TabPage tabDatabase, tabAuto, tabGitHub, tabScanner, tabIpc;
        
        // Veritabanı Sekmesi
        private ListView lvSignatures;
        private TextBox txtHash, txtThreatName, txtSearch;
        private Button btnAdd, btnDelete, btnClear, btnImportTxt, btnImportJson, btnExportJson, btnExportTxt;
        private ProgressBar progressBar;
        private Label lblStats;

        // Otomatik İzleyici Sekmesi
        private TextBox txtWatchFile;
        private Button btnSelectWatchFile;
        private CheckBox chkWatchFile, chkWatchClipboard, chkAutoPush;
        private RichTextBox rtbAutoLog;
        private FileSystemWatcher _fileWatcher;
        private System.Windows.Forms.Timer _clipboardTimer;
        private System.Windows.Forms.Timer _debounceTimer;
        private string _lastClipboardText = string.Empty;

        // GitHub Sekmesi
        private TextBox txtGhRepo, txtGhBranch, txtGhToken, txtGhPath;
        private RichTextBox rtbGhLog;
        private Button btnGhPush;
        private CheckBox chkSaveToken;

        // Scanner Sekmesi
        private TextBox txtScanFile, txtResultMd5, txtResultSha1, txtResultSha256;
        private Label lblScanVerdict;
        private Button btnSelectFile, btnAddScannedHash;

        // IPC Sekmesi
        private RichTextBox rtbIpcLog;
        private Button btnTestIpc, btnClearIpcLog;

        // Durum Çubuğu
        private StatusStrip statusStrip;
        private ToolStripStatusLabel lblStatusTotal, lblStatusVisible, lblStatusAuto, lblStatusIpc;

        public MainForm()
        {
            InitializeRetroComponents();
            InitializeEngine();
            InitializeAutoWatchers();
        }

        private void InitializeRetroComponents()
        {
            // Form Ayarları (Retro Windows XP Luna Look)
            this.Text = "SAMET-AV THREAT INTELLIGENCE | HASH DATABASE STUDIO v1.0 (Windows XP Luna)";
            this.Size = new Size(920, 680);
            this.MinimumSize = new Size(820, 580);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Font = new Font("Tahoma", 8.25f, FontStyle.Regular);
            this.BackColor = Color.FromArgb(236, 233, 216); // Classic Windows XP Dialog Color

            // Üst Başlık Bannerı (Windows XP Luna Blue)
            Panel headerPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 54,
                BackColor = Color.FromArgb(0, 85, 234),
                Padding = new Padding(12, 6, 12, 6)
            };

            Label lblHeaderTitle = new Label
            {
                Text = "🛡️ SAMET-AV SIGNATURE STUDIO & THREAT DATABASE",
                Font = new Font("Tahoma", 11.0f, FontStyle.Bold),
                ForeColor = Color.White,
                AutoSize = true,
                Location = new Point(12, 8)
            };

            Label lblHeaderSub = new Label
            {
                Text = "1M+ Hash Otomatik Kaydetme & İzleme • Anında Diske Yazma • GitHub Pages Senkronizasyon",
                Font = new Font("Tahoma", 8.0f, FontStyle.Regular),
                ForeColor = Color.FromArgb(220, 235, 255),
                AutoSize = true,
                Location = new Point(14, 30)
            };

            headerPanel.Controls.Add(lblHeaderTitle);
            headerPanel.Controls.Add(lblHeaderSub);
            this.Controls.Add(headerPanel);

            // TabControl
            tabControl = new TabControl
            {
                Dock = DockStyle.Fill,
                Font = new Font("Tahoma", 8.5f, FontStyle.Bold),
                Padding = new Point(12, 5)
            };

            // Sekmeleri Oluştur
            tabDatabase = new TabPage("📋 İmza Veritabanı");
            tabAuto = new TabPage("⚡ Otomatik Hash İzleyici");
            tabGitHub = new TabPage("☁️ GitHub Pages Sync");
            tabScanner = new TabPage("🔍 Dosya Analiz & Tara");
            tabIpc = new TabPage("📡 EXE Haberleşme (IPC)");

            BuildDatabaseTab();
            BuildAutoTab();
            BuildGitHubTab();
            BuildScannerTab();
            BuildIpcTab();

            tabControl.TabPages.Add(tabDatabase);
            tabControl.TabPages.Add(tabAuto);
            tabControl.TabPages.Add(tabGitHub);
            tabControl.TabPages.Add(tabScanner);
            tabControl.TabPages.Add(tabIpc);

            this.Controls.Add(tabControl);
            headerPanel.BringToFront();

            // Durum Çubuğu
            statusStrip = new StatusStrip { BackColor = Color.FromArgb(236, 233, 216) };
            lblStatusTotal = new ToolStripStatusLabel("Toplam İmza: 0") { BorderSides = ToolStripStatusLabelBorderSides.Right };
            lblStatusVisible = new ToolStripStatusLabel("Görüntülenen: 0") { BorderSides = ToolStripStatusLabelBorderSides.Right };
            lblStatusAuto = new ToolStripStatusLabel("Otomatik Kayıt: AKTİF") { BorderSides = ToolStripStatusLabelBorderSides.Right, ForeColor = Color.DarkGreen };
            lblStatusIpc = new ToolStripStatusLabel("IPC: \\\\.\\pipe\\AntivirusHashPipe") { Spring = true, TextAlign = ContentAlignment.MiddleRight };

            statusStrip.Items.AddRange(new ToolStripItem[] { lblStatusTotal, lblStatusVisible, lblStatusAuto, lblStatusIpc });
            this.Controls.Add(statusStrip);
        }

        #region TAB 1: İmza Veritabanı

        private void BuildDatabaseTab()
        {
            tabDatabase.Font = new Font("Tahoma", 8.25f, FontStyle.Regular);
            tabDatabase.BackColor = Color.FromArgb(236, 233, 216);

            // 1. Manuel Ekleme Kutusu (Windows XP Tarzı)
            GroupBox gbAdd = new GroupBox
            {
                Text = "🛡️ Yeni SHA-256 İmza Ekleme İstasyonu (Otomatik Kalıcı Kaydeder)",
                Dock = DockStyle.Top,
                Height = 70,
                Padding = new Padding(8)
            };

            Label lblH = new Label { Text = "Eklenecek SHA:", AutoSize = true, Location = new Point(12, 26), Font = new Font("Tahoma", 8.25f, FontStyle.Bold) };
            txtHash = new TextBox { Location = new Point(105, 23), Width = 310, Font = new Font("Consolas", 8.5f) };

            Label lblT = new Label { Text = "Tehdit Tanımı:", AutoSize = true, Location = new Point(425, 26), Font = new Font("Tahoma", 8.25f, FontStyle.Bold) };
            txtThreatName = new TextBox { Location = new Point(508, 23), Width = 150, Text = "Trojan.Win32.PufaAv.Generic" };

            btnAdd = new Button
            {
                Text = "➕ SHA'yı Ekle",
                Location = new Point(668, 21),
                Width = 110,
                Height = 26,
                Font = new Font("Tahoma", 8.25f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnAdd.Click += (s, e) => AddSingleHash();

            gbAdd.Controls.AddRange(new Control[] { lblH, txtHash, lblT, txtThreatName, btnAdd });

            // 2. Arama ve Filtreleme Çubuğu
            Panel searchPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 35,
                Padding = new Padding(4)
            };

            Label lblS = new Label { Text = "🔍 Hızlı Ara (O(1)):", AutoSize = true, Location = new Point(12, 9), Font = new Font("Tahoma", 8.25f, FontStyle.Bold) };
            txtSearch = new TextBox { Location = new Point(135, 6), Width = 300, Font = new Font("Consolas", 8.5f) };
            txtSearch.TextChanged += (s, e) => SearchDatabase(txtSearch.Text);

            lblStats = new Label
            {
                Text = "Kayıtlar bellekte ve database.json dosyasında senkronize.",
                AutoSize = true,
                Location = new Point(450, 9),
                ForeColor = Color.DarkSlateGray
            };

            searchPanel.Controls.AddRange(new Control[] { lblS, txtSearch, lblStats });

            // 3. VirtualMode ListView
            lvSignatures = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                VirtualMode = true,
                Font = new Font("Consolas", 8.5f)
            };

            lvSignatures.Columns.Add("#", 60);
            lvSignatures.Columns.Add("Hash (SHA256 / MD5)", 430);
            lvSignatures.Columns.Add("Zararlı Tanımı (Threat Name)", 260);

            lvSignatures.RetrieveVirtualItem += LvSignatures_RetrieveVirtualItem;
            lvSignatures.KeyDown += LvSignatures_KeyDown;

            // 4. Alt Butonlar ve İlerleme Çubuğu
            Panel bottomPanel = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 72,
                Padding = new Padding(6)
            };

            progressBar = new ProgressBar
            {
                Dock = DockStyle.Top,
                Height = 14,
                Visible = false
            };

            Panel btnPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(2) };

            btnImportTxt = new Button { Text = "📂 Toplu TXT İçe Aktar", Size = new Size(140, 30), Location = new Point(6, 12), Cursor = Cursors.Hand };
            btnImportTxt.Click += async (s, e) => await ImportTxtAsync();

            btnImportJson = new Button { Text = "📄 JSON İçe Aktar", Size = new Size(120, 30), Location = new Point(152, 12), Cursor = Cursors.Hand };
            btnImportJson.Click += (s, e) => ImportJson();

            btnExportJson = new Button { Text = "💾 database.json Kaydet", Size = new Size(150, 30), Location = new Point(278, 12), Cursor = Cursors.Hand, Font = new Font("Tahoma", 8.25f, FontStyle.Bold) };
            btnExportJson.Click += (s, e) => ExportJson();

            btnExportTxt = new Button { Text = "📑 TXT Olarak Dışa Aktar", Size = new Size(140, 30), Location = new Point(434, 12), Cursor = Cursors.Hand };
            btnExportTxt.Click += (s, e) => ExportTxt();

            btnDelete = new Button { Text = "❌ Seçileni Sil", Size = new Size(100, 30), Location = new Point(580, 12), ForeColor = Color.DarkRed };
            btnDelete.Click += (s, e) => DeleteSelected();

            btnClear = new Button { Text = "🗑️ Tümünü Temizle", Size = new Size(110, 30), Location = new Point(686, 12), ForeColor = Color.Red };
            btnClear.Click += (s, e) => ClearAll();

            btnPanel.Controls.AddRange(new Control[] { btnImportTxt, btnImportJson, btnExportJson, btnExportTxt, btnDelete, btnClear });

            bottomPanel.Controls.Add(btnPanel);
            bottomPanel.Controls.Add(progressBar);

            tabDatabase.Controls.Add(lvSignatures);
            tabDatabase.Controls.Add(bottomPanel);
            tabDatabase.Controls.Add(searchPanel);
            tabDatabase.Controls.Add(gbAdd);
        }

        private void LvSignatures_RetrieveVirtualItem(object sender, RetrieveVirtualItemEventArgs e)
        {
            string hash = _db.GetHashAt(e.ItemIndex);
            string threat = _db.GetThreatAt(e.ItemIndex);

            var item = new ListViewItem((e.ItemIndex + 1).ToString());
            item.SubItems.Add(hash);
            item.SubItems.Add(threat);
            e.Item = item;
        }

        private void LvSignatures_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Delete)
            {
                DeleteSelected();
            }
        }

        #endregion

        #region TAB 2: Otomatik Hash İzleyici & Ekleyici

        private void BuildAutoTab()
        {
            tabAuto.Font = new Font("Tahoma", 8.25f, FontStyle.Regular);
            tabAuto.BackColor = Color.FromArgb(236, 233, 216);

            // 1. Canlı Dosya İzleyici Grubu
            GroupBox gbWatcher = new GroupBox
            {
                Text = "📁 İmza Dosyası Canlı İzleme (Dosya Değiştikçe Otomatik Ekler)",
                Dock = DockStyle.Top,
                Height = 120,
                Padding = new Padding(10)
            };

            Label lblW = new Label { Text = "İzlenecek Dosya:", Location = new Point(14, 26), AutoSize = true, Font = new Font("Tahoma", 8.25f, FontStyle.Bold) };
            txtWatchFile = new TextBox
            {
                Location = new Point(120, 23),
                Width = 560,
                Text = @"C:\Users\altan\Desktop\PufaAv\build\signatures\external_sha256.txt"
            };

            btnSelectWatchFile = new Button
            {
                Text = "📂 Gözat...",
                Location = new Point(690, 22),
                Width = 90,
                Height = 24,
                Cursor = Cursors.Hand
            };
            btnSelectWatchFile.Click += (s, e) => SelectWatchFile();

            chkWatchFile = new CheckBox
            {
                Text = "⚡ Bu Dosyayı Canlı İzle (Dosya kaydedildiği veya yeni satır eklendiği anda otomatik veritabanına ekle)",
                Location = new Point(120, 55),
                AutoSize = true,
                Font = new Font("Tahoma", 8.25f, FontStyle.Bold),
                ForeColor = Color.FromArgb(0, 50, 140)
            };
            chkWatchFile.CheckedChanged += (s, e) => ToggleFileWatcher(chkWatchFile.Checked);

            gbWatcher.Controls.AddRange(new Control[] { lblW, txtWatchFile, btnSelectWatchFile, chkWatchFile });

            // 2. Diğer Otomasyon Ayarları
            GroupBox gbOptions = new GroupBox
            {
                Text = "⚙️ Akıllı Otomatik Yakalama & Senkronizasyon",
                Dock = DockStyle.Top,
                Height = 90,
                Padding = new Padding(10)
            };

            chkWatchClipboard = new CheckBox
            {
                Text = "📋 Windows Panosunu (Clipboard) İzle: 64 Karakterli SHA-256 Kopyalandığında Otomatik Ekle",
                Location = new Point(16, 24),
                AutoSize = true,
                Font = new Font("Tahoma", 8.25f, FontStyle.Bold)
            };
            chkWatchClipboard.CheckedChanged += (s, e) => ToggleClipboardWatcher(chkWatchClipboard.Checked);

            chkAutoPush = new CheckBox
            {
                Text = "🚀 Yeni Hash Eklendiğinde Otomatik Olarak GitHub Pages'e Yükle (Auto-Push)",
                Location = new Point(16, 52),
                AutoSize = true,
                Font = new Font("Tahoma", 8.25f, FontStyle.Bold),
                ForeColor = Color.DarkGreen
            };

            gbOptions.Controls.AddRange(new Control[] { chkWatchClipboard, chkAutoPush });

            // 3. Otomatik İşlem Terminal Günlüğü
            GroupBox gbLog = new GroupBox
            {
                Text = "📡 Otomatik Ekleme ve Olay Günlüğü",
                Dock = DockStyle.Fill,
                Padding = new Padding(8)
            };

            rtbAutoLog = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(12, 16, 22),
                ForeColor = Color.FromArgb(57, 255, 20),
                Font = new Font("Consolas", 9.0f),
                ReadOnly = true
            };

            gbLog.Controls.Add(rtbAutoLog);

            tabAuto.Controls.Add(gbLog);
            tabAuto.Controls.Add(gbOptions);
            tabAuto.Controls.Add(gbWatcher);
        }

        #endregion

        #region TAB 3: GitHub Pages Senkronizasyonu

        private void BuildGitHubTab()
        {
            tabGitHub.Font = new Font("Tahoma", 8.25f, FontStyle.Regular);
            tabGitHub.BackColor = Color.FromArgb(236, 233, 216);

            GroupBox gbSettings = new GroupBox
            {
                Text = "GitHub Repository & Pages Yapılandırması",
                Dock = DockStyle.Top,
                Height = 160,
                Padding = new Padding(12)
            };

            Label l1 = new Label { Text = "Repository:", Location = new Point(16, 26), AutoSize = true };
            txtGhRepo = new TextBox { Location = new Point(100, 23), Width = 260, Text = "Samettr08/Samettr08.github.io" };

            Label l2 = new Label { Text = "Branch:", Location = new Point(380, 26), AutoSize = true };
            txtGhBranch = new TextBox { Location = new Point(440, 23), Width = 100, Text = "main" };

            Label l3 = new Label { Text = "Dosya Yolu:", Location = new Point(560, 26), AutoSize = true };
            txtGhPath = new TextBox { Location = new Point(635, 23), Width = 140, Text = "database.json" };

            Label l4 = new Label { Text = "Personal Access Token (PAT):", Location = new Point(16, 62), AutoSize = true };
            txtGhToken = new TextBox { Location = new Point(180, 59), Width = 400, UseSystemPasswordChar = true };

            chkSaveToken = new CheckBox { Text = "Token'ı yerel config'e kaydet", Location = new Point(590, 60), AutoSize = true, Checked = true };

            btnGhPush = new Button
            {
                Text = "🚀 database.json'ı GitHub Pages'e Yayınla (Sync)",
                Location = new Point(180, 95),
                Width = 350,
                Height = 36,
                BackColor = Color.FromArgb(0, 100, 0),
                ForeColor = Color.White,
                Font = new Font("Tahoma", 9.0f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnGhPush.Click += async (s, e) => await SyncToGitHubAsync();

            gbSettings.Controls.AddRange(new Control[] { l1, txtGhRepo, l2, txtGhBranch, l3, txtGhPath, l4, txtGhToken, chkSaveToken, btnGhPush });

            GroupBox gbLog = new GroupBox
            {
                Text = "Senkronizasyon Durum & API Günlüğü",
                Dock = DockStyle.Fill,
                Padding = new Padding(8)
            };

            rtbGhLog = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(16, 20, 28),
                ForeColor = Color.FromArgb(57, 255, 20),
                Font = new Font("Consolas", 9.0f),
                ReadOnly = true
            };

            gbLog.Controls.Add(rtbGhLog);

            tabGitHub.Controls.Add(gbLog);
            tabGitHub.Controls.Add(gbSettings);

            LoadGitHubConfig();
        }

        #endregion

        #region TAB 4: Scanner (Dosya Hash & Analiz)

        private void BuildScannerTab()
        {
            tabScanner.Font = new Font("Tahoma", 8.25f, FontStyle.Regular);
            tabScanner.BackColor = Color.FromArgb(236, 233, 216);

            GroupBox gbFile = new GroupBox
            {
                Text = "Dosya Seçimi & Hash Çıkarma",
                Dock = DockStyle.Top,
                Height = 220,
                Padding = new Padding(12)
            };

            Label lblF = new Label { Text = "Hedef Dosya:", Location = new Point(16, 28), AutoSize = true };
            txtScanFile = new TextBox { Location = new Point(100, 25), Width = 540, ReadOnly = true };
            btnSelectFile = new Button { Text = "📂 Dosya Seç...", Location = new Point(650, 24), Width = 110, Height = 25, Cursor = Cursors.Hand };
            btnSelectFile.Click += (s, e) => SelectAndScanFile();

            Label lMd5 = new Label { Text = "MD5:", Location = new Point(16, 68), AutoSize = true };
            txtResultMd5 = new TextBox { Location = new Point(100, 65), Width = 480, ReadOnly = true, Font = new Font("Consolas", 8.5f) };

            Label lSha1 = new Label { Text = "SHA-1:", Location = new Point(16, 98), AutoSize = true };
            txtResultSha1 = new TextBox { Location = new Point(100, 95), Width = 480, ReadOnly = true, Font = new Font("Consolas", 8.5f) };

            Label lSha256 = new Label { Text = "SHA-256:", Location = new Point(16, 128), AutoSize = true };
            txtResultSha256 = new TextBox { Location = new Point(100, 125), Width = 480, ReadOnly = true, Font = new Font("Consolas", 8.5f) };

            lblScanVerdict = new Label
            {
                Text = "Bir dosya seçin veya sürükleyip bırakın.",
                Location = new Point(100, 165),
                AutoSize = true,
                Font = new Font("Tahoma", 10.0f, FontStyle.Bold),
                ForeColor = Color.DarkSlateGray
            };

            btnAddScannedHash = new Button
            {
                Text = "➕ Bu Hash'i Veritabanına Ekle",
                Location = new Point(590, 123),
                Width = 170,
                Height = 28,
                Enabled = false,
                Cursor = Cursors.Hand
            };
            btnAddScannedHash.Click += (s, e) => AddScannedToDatabase();

            gbFile.Controls.AddRange(new Control[] { lblF, txtScanFile, btnSelectFile, lMd5, txtResultMd5, lSha1, txtResultSha1, lSha256, txtResultSha256, lblScanVerdict, btnAddScannedHash });

            tabScanner.Controls.Add(gbFile);

            tabScanner.AllowDrop = true;
            tabScanner.DragEnter += (s, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            tabScanner.DragDrop += (s, e) =>
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files != null && files.Length > 0) ScanSelectedFile(files[0]);
            };
        }

        #endregion

        #region TAB 5: IPC Monitörü

        private void BuildIpcTab()
        {
            tabIpc.Font = new Font("Tahoma", 8.25f, FontStyle.Regular);
            tabIpc.BackColor = Color.FromArgb(236, 233, 216);

            Panel topPanel = new Panel { Dock = DockStyle.Top, Height = 55, Padding = new Padding(8) };
            Label lblIpcInfo = new Label
            {
                Text = "📡 Named Pipe: \\\\.\\pipe\\AntivirusHashPipe  (Diğer antivirüs EXE'leriniz buradan milisaniyede sorgu yapar)",
                Location = new Point(12, 10),
                AutoSize = true,
                Font = new Font("Tahoma", 8.5f, FontStyle.Bold)
            };

            btnTestIpc = new Button { Text = "🧪 Kendine Test Ping'i Gönder", Location = new Point(12, 28), Width = 180, Height = 24, Cursor = Cursors.Hand };
            btnTestIpc.Click += (s, e) => TestIpcLoopback();

            btnClearIpcLog = new Button { Text = "Günlüğü Temizle", Location = new Point(200, 28), Width = 110, Height = 24 };
            btnClearIpcLog.Click += (s, e) => rtbIpcLog.Clear();

            topPanel.Controls.AddRange(new Control[] { lblIpcInfo, btnTestIpc, btnClearIpcLog });

            rtbIpcLog = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(10, 15, 10),
                ForeColor = Color.FromArgb(50, 220, 50),
                Font = new Font("Consolas", 9.0f),
                ReadOnly = true
            };

            tabIpc.Controls.Add(rtbIpcLog);
            tabIpc.Controls.Add(topPanel);
        }

        #endregion

        #region Motor Başlatma & Otomatik Kayıt (Auto-Save)

        private void InitializeEngine()
        {
            // Varsa başlangıç database.json dosyasını yükle
            string defaultDbPath = GetDatabasePath();
            if (File.Exists(defaultDbPath))
            {
                _db.LoadFromJson(defaultDbPath);
            }
            else
            {
                // Tek Taşınabilir (Portable) Mod: Yerel dosya yoksa canlı GitHub Pages'ten otomatik indir
                try
                {
                    System.Net.ServicePointManager.SecurityProtocol = (System.Net.SecurityProtocolType)3072; // Tls12
                    using (var wc = new System.Net.WebClient { Encoding = Encoding.UTF8 })
                    {
                        string json = wc.DownloadString("https://samettr08.github.io/database.json");
                        File.WriteAllText(defaultDbPath, json, Encoding.UTF8);
                        _db.LoadFromJson(defaultDbPath);
                    }
                }
                catch { }
            }

            UpdateListCount();

            // IPC Sunucusunu Başlat
            try
            {
                _ipcServer = new IpcServer(_db);
                _ipcServer.OnLog += msg =>
                {
                    if (this.IsHandleCreated)
                    {
                        this.BeginInvoke(new Action(() =>
                        {
                            rtbIpcLog.AppendText(msg + Environment.NewLine);
                            rtbIpcLog.ScrollToCaret();
                        }));
                    }
                };
                _ipcServer.Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show("IPC Sunucusu başlatılamadı: " + ex.Message, "IPC Hatası", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private string GetDatabasePath()
        {
            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "database.json");
        }

        /// <summary>
        /// Her hash eklendiğinde/silindiğinde database.json dosyasını hemen yerel diske yazar.
        /// Böylece program kapatılıp açılsa (restart) veya F5 atılsa bile hiçbir veri kaybolmaz!
        /// </summary>
        private void AutoSaveDatabase()
        {
            try
            {
                string dbPath = GetDatabasePath();
                _db.ExportToJson(dbPath);

                if (chkAutoPush != null && chkAutoPush.Checked)
                {
                    // Arka planda sessizce GitHub'a push et
                    Task.Run(() => SilentGitHubPush());
                }
            }
            catch (Exception ex)
            {
                LogAuto("Otomatik Kayıt Hatası: " + ex.Message);
            }
        }

        private void SilentGitHubPush()
        {
            try
            {
                string localPath = GetDatabasePath();
                string token = txtGhToken.Text.Trim();
                if (string.IsNullOrEmpty(token)) return;

                _ghSync.RepoFullName = txtGhRepo.Text.Trim();
                _ghSync.Branch = txtGhBranch.Text.Trim();
                _ghSync.FilePath = txtGhPath.Text.Trim();
                _ghSync.Token = token;

                var res = _ghSync.PushDatabase(localPath, log =>
                {
                    if (this.IsHandleCreated)
                    {
                        this.BeginInvoke(new Action(() =>
                        {
                            rtbGhLog.AppendText(log + Environment.NewLine);
                            rtbGhLog.ScrollToCaret();
                        }));
                    }
                });

                if (res.Success)
                {
                    LogAuto("🚀 Otomatik Push Başarılı: database.json GitHub Pages'e yüklendi!");
                }
            }
            catch { }
        }

        private void UpdateListCount()
        {
            lvSignatures.VirtualListSize = _db.VisibleCount;
            lblStatusTotal.Text = string.Format("Toplam İmza: {0:N0}", _db.Count);
            lblStatusVisible.Text = string.Format("Görüntülenen: {0:N0}", _db.VisibleCount);
            lblStats.Text = string.Format("{0:N0} imza veritabanında aktif (Diske otomatik kaydedildi).", _db.Count);
            lvSignatures.Invalidate();
        }

        private void AddSingleHash()
        {
            string hash = (txtHash.Text ?? string.Empty).Trim();
            string threat = (txtThreatName.Text ?? string.Empty).Trim();

            if (string.IsNullOrEmpty(hash))
            {
                MessageBox.Show("Lütfen geçerli bir SHA-256 veya MD5 Hash değeri girin!", "Uyarı", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (_db.Add(hash, threat))
            {
                txtHash.Clear();
                UpdateListCount();
                AutoSaveDatabase();
                MessageBox.Show("İmza başarıyla eklendi ve database.json dosyasına KALICI OLARAK kaydedildi.", "Başarılı & Kaydedildi", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                UpdateListCount();
                AutoSaveDatabase();
                MessageBox.Show("Bu hash zaten veritabanında vardı, tehdit tanımı güncellendi ve kaydedildi.", "Bilgi", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void DeleteSelected()
        {
            if (lvSignatures.SelectedIndices.Count == 0)
            {
                MessageBox.Show("Lütfen silmek için listeden bir veya birden fazla imza seçin.", "Bilgi", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            var confirm = MessageBox.Show(string.Format("Seçili {0} adet imzayı silmek istediğinize emin misiniz?", lvSignatures.SelectedIndices.Count),
                "Silme Onayı", MessageBoxButtons.YesNo, MessageBoxIcon.Question);

            if (confirm != DialogResult.Yes) return;

            var indices = new int[lvSignatures.SelectedIndices.Count];
            lvSignatures.SelectedIndices.CopyTo(indices, 0);
            Array.Sort(indices);
            Array.Reverse(indices);

            foreach (int idx in indices)
            {
                string hash = _db.GetHashAt(idx);
                _db.Remove(hash);
            }

            UpdateListCount();
            AutoSaveDatabase();
        }

        private void ClearAll()
        {
            var confirm = MessageBox.Show("Veritabanındaki TÜM imzalar silinecek! Emin misiniz?", "Tümünü Temizle", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm == DialogResult.Yes)
            {
                _db.Clear();
                UpdateListCount();
                AutoSaveDatabase();
            }
        }

        private void SearchDatabase(string query)
        {
            _db.ApplyFilter(query);
            UpdateListCount();
        }

        private async Task ImportTxtAsync()
        {
            using (var ofd = new OpenFileDialog { Filter = "Metin Dosyaları (*.txt)|*.txt|Tüm Dosyalar (*.*)|*.*", Title = "Toplu Hash Listesi Seç" })
            {
                if (ofd.ShowDialog() != DialogResult.OK) return;

                progressBar.Visible = true;
                progressBar.Style = ProgressBarStyle.Marquee;
                btnImportTxt.Enabled = false;

                var sw = Stopwatch.StartNew();
                BulkResult res = null;

                await Task.Run(() =>
                {
                    res = _db.ImportFromTxt(ofd.FileName, processed =>
                    {
                        this.BeginInvoke(new Action(() =>
                        {
                            lblStats.Text = string.Format("İşleniyor: {0:N0} satır...", processed);
                        }));
                    });
                });

                sw.Stop();
                progressBar.Visible = false;
                btnImportTxt.Enabled = true;

                UpdateListCount();
                AutoSaveDatabase(); // İçe aktarma biter bitmez kalıcı kaydet!

                MessageBox.Show(string.Format(
                    "Toplu içe aktarma tamamlandı ve database.json dosyasına kaydedildi!\n\n" +
                    "Geçen Süre: {0:N2} saniye\n" +
                    "Toplam Okunan Satır: {1:N0}\n" +
                    "Yeni Eklenen İmza: {2:N0}\n" +
                    "Güncellenen Mevcut: {3:N0}\n" +
                    "Dosya İçi Mükerrer: {4:N0}\n" +
                    "Geçersiz Format: {5:N0}",
                    sw.Elapsed.TotalSeconds, res.TotalLines, res.AddedCount, res.ExistingUpdatedCount, res.DuplicatesInFile, res.InvalidCount),
                    "İçe Aktarma Başarılı", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void ImportJson()
        {
            using (var ofd = new OpenFileDialog { Filter = "JSON Dosyaları (*.json)|*.json|Tüm Dosyalar (*.*)|*.*", Title = "JSON Veritabanı Seç" })
            {
                if (ofd.ShowDialog() != DialogResult.OK) return;

                var res = _db.LoadFromJson(ofd.FileName);
                UpdateListCount();
                AutoSaveDatabase();
                MessageBox.Show(string.Format("{0:N0} adet imza JSON dosyasından başarıyla yüklendi ve kaydedildi.", res.AddedCount), "Yüklendi", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void ExportJson()
        {
            using (var sfd = new SaveFileDialog { Filter = "JSON Veritabanı (*.json)|*.json", FileName = "database.json", Title = "database.json Olarak Kaydet" })
            {
                if (sfd.ShowDialog() != DialogResult.OK) return;

                _db.ExportToJson(sfd.FileName);
                MessageBox.Show("Veritabanı başarıyla kaydedildi:\n" + sfd.FileName, "Kayıt Başarılı", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void ExportTxt()
        {
            using (var sfd = new SaveFileDialog { Filter = "Metin Dosyası (*.txt)|*.txt", FileName = "hashes.txt", Title = "TXT Olarak Dışa Aktar" })
            {
                if (sfd.ShowDialog() != DialogResult.OK) return;

                _db.ExportToTxt(sfd.FileName);
                MessageBox.Show("TXT listesi başarıyla kaydedildi:\n" + sfd.FileName, "Kayıt Başarılı", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        #endregion

        #region OTOMATİK İZLEYİCİLER (File Watcher & Clipboard Monitor)

        private void InitializeAutoWatchers()
        {
            // Debounce timer (dosya çok hızlı ardışık yazıldığında çakışmayı önler)
            _debounceTimer = new System.Windows.Forms.Timer { Interval = 800 };
            _debounceTimer.Tick += (s, e) =>
            {
                _debounceTimer.Stop();
                ProcessWatchedFileChange();
            };

            // Pano kontrol zamanlayıcısı (her 800ms)
            _clipboardTimer = new System.Windows.Forms.Timer { Interval = 800 };
            _clipboardTimer.Tick += (s, e) => CheckClipboardForSha();
        }

        private void SelectWatchFile()
        {
            using (var ofd = new OpenFileDialog { Title = "İzlenecek İmza Dosyasını Seçin", Filter = "Metin Dosyaları (*.txt)|*.txt|Tüm Dosyalar (*.*)|*.*" })
            {
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    txtWatchFile.Text = ofd.FileName;
                    if (chkWatchFile.Checked)
                    {
                        ToggleFileWatcher(false);
                        ToggleFileWatcher(true);
                    }
                }
            }
        }

        private void ToggleFileWatcher(bool enable)
        {
            if (enable)
            {
                string path = txtWatchFile.Text.Trim();
                if (!File.Exists(path))
                {
                    MessageBox.Show("İzlenecek dosya bulunamadı:\n" + path, "Hata", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    chkWatchFile.Checked = false;
                    return;
                }

                try
                {
                    string dir = Path.GetDirectoryName(path);
                    string fileName = Path.GetFileName(path);

                    if (_fileWatcher != null)
                    {
                        _fileWatcher.EnableRaisingEvents = false;
                        _fileWatcher.Dispose();
                    }

                    _fileWatcher = new FileSystemWatcher(dir, fileName)
                    {
                        NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName
                    };

                    _fileWatcher.Changed += (s, e) =>
                    {
                        this.BeginInvoke(new Action(() =>
                        {
                            _debounceTimer.Stop();
                            _debounceTimer.Start();
                        }));
                    };

                    _fileWatcher.EnableRaisingEvents = true;
                    LogAuto("🟢 Dosya Canlı İzleme Başlatıldı: " + path);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("İzleyici başlatılamadı: " + ex.Message, "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    chkWatchFile.Checked = false;
                }
            }
            else
            {
                if (_fileWatcher != null)
                {
                    _fileWatcher.EnableRaisingEvents = false;
                    _fileWatcher.Dispose();
                    _fileWatcher = null;
                }
                LogAuto("⚪ Dosya Canlı İzleme Durduruldu.");
            }
        }

        private void ProcessWatchedFileChange()
        {
            string path = txtWatchFile.Text.Trim();
            if (!File.Exists(path)) return;

            LogAuto("⚡ İzlenen dosyada değişiklik algılandı! Yeni imzalar taranıyor: " + Path.GetFileName(path));

            Task.Run(() =>
            {
                // Dosya kilidinin serbest kalması için kısa bekleme
                System.Threading.Thread.Sleep(300);
                var res = _db.ImportFromTxt(path);

                this.BeginInvoke(new Action(() =>
                {
                    UpdateListCount();
                    AutoSaveDatabase();
                    LogAuto(string.Format("✅ Otomatik İçe Aktarma: {0:N0} yeni imza eklendi, toplam {1:N0} imza aktif.", res.AddedCount, _db.Count));
                }));
            });
        }

        private void ToggleClipboardWatcher(bool enable)
        {
            if (enable)
            {
                _lastClipboardText = string.Empty;
                _clipboardTimer.Start();
                LogAuto("🟢 Pano (Clipboard) Otomatik SHA Algılayıcı Başlatıldı.");
            }
            else
            {
                _clipboardTimer.Stop();
                LogAuto("⚪ Pano Otomatik Algılayıcı Durduruldu.");
            }
        }

        private void CheckClipboardForSha()
        {
            try
            {
                if (!Clipboard.ContainsText()) return;
                string text = Clipboard.GetText();
                if (string.IsNullOrEmpty(text) || text == _lastClipboardText) return;

                _lastClipboardText = text;
                string clean = text.Trim().ToLowerInvariant();

                // 64 karakterli SHA-256 mı?
                if (clean.Length == 64 && Regex.IsMatch(clean, "^[a-f0-9]{64}$"))
                {
                    string existingThreat;
                    if (!_db.CheckHash(clean, out existingThreat))
                    {
                        string name = "Clipboard.Captured." + DateTime.Now.ToString("HHmmss");
                        _db.Add(clean, name);
                        UpdateListCount();
                        AutoSaveDatabase();

                        LogAuto(string.Format("📋 [PANO YAKALANDI] Yeni SHA-256 otomatik eklendi: {0} ({1})", clean.Substring(0, 16) + "...", name));
                    }
                }
            }
            catch { }
        }

        private void LogAuto(string msg)
        {
            if (this.IsHandleCreated)
            {
                this.BeginInvoke(new Action(() =>
                {
                    rtbAutoLog.AppendText(string.Format("[{0}] {1}\n", DateTime.Now.ToString("HH:mm:ss"), msg));
                    rtbAutoLog.ScrollToCaret();
                }));
            }
        }

        #endregion

        #region GitHub Senkronizasyon Olayları

        private async Task SyncToGitHubAsync()
        {
            string repo = (txtGhRepo.Text ?? string.Empty).Trim();
            string branch = (txtGhBranch.Text ?? string.Empty).Trim();
            string path = (txtGhPath.Text ?? string.Empty).Trim();
            string token = (txtGhToken.Text ?? string.Empty).Trim();

            if (string.IsNullOrEmpty(token))
            {
                MessageBox.Show("Lütfen GitHub Personal Access Token (PAT) girin!", "Token Eksik", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string localPath = GetDatabasePath();
            _db.ExportToJson(localPath);

            _ghSync.RepoFullName = repo;
            _ghSync.Branch = branch;
            _ghSync.FilePath = path;
            _ghSync.Token = token;

            if (chkSaveToken.Checked)
            {
                SaveGitHubConfig();
            }

            btnGhPush.Enabled = false;
            btnGhPush.Text = "⏳ GitHub'a İletiliyor...";

            rtbGhLog.AppendText(string.Format("\n=== Senkronizasyon Başlatıldı ({0}) ===\n", DateTime.Now.ToString("HH:mm:ss")));

            SyncResult result = null;
            await Task.Run(() =>
            {
                result = _ghSync.PushDatabase(localPath, log =>
                {
                    this.BeginInvoke(new Action(() =>
                    {
                        rtbGhLog.AppendText(log + Environment.NewLine);
                        rtbGhLog.ScrollToCaret();
                    }));
                });
            });

            btnGhPush.Enabled = true;
            btnGhPush.Text = "🚀 database.json'ı GitHub Pages'e Yayınla (Sync)";

            if (result.Success)
            {
                MessageBox.Show(result.Message, "Senkronizasyon Başarılı", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("Hata oluştu:\n" + result.Message, "GitHub Hatası", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void SaveGitHubConfig()
        {
            try
            {
                string cfgPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "github_config.ini");
                string content = string.Format("repo={0}\nbranch={1}\npath={2}\ntoken={3}",
                    txtGhRepo.Text.Trim(), txtGhBranch.Text.Trim(), txtGhPath.Text.Trim(), txtGhToken.Text.Trim());
                File.WriteAllText(cfgPath, content, Encoding.UTF8);
            }
            catch { }
        }

        private void LoadGitHubConfig()
        {
            try
            {
                string cfgPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "github_config.ini");
                if (File.Exists(cfgPath))
                {
                    string[] lines = File.ReadAllLines(cfgPath, Encoding.UTF8);
                    foreach (var line in lines)
                    {
                        if (line.StartsWith("repo=")) txtGhRepo.Text = line.Substring(5).Trim();
                        if (line.StartsWith("branch=")) txtGhBranch.Text = line.Substring(7).Trim();
                        if (line.StartsWith("path=")) txtGhPath.Text = line.Substring(5).Trim();
                        if (line.StartsWith("token=")) txtGhToken.Text = line.Substring(6).Trim();
                    }
                }
            }
            catch { }
        }

        #endregion

        #region Scanner Olayları

        private void SelectAndScanFile()
        {
            using (var ofd = new OpenFileDialog { Title = "Taranacak Dosyayı Seçin", Filter = "Tüm Dosyalar (*.*)|*.*" })
            {
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    ScanSelectedFile(ofd.FileName);
                }
            }
        }

        private void ScanSelectedFile(string filePath)
        {
            try
            {
                txtScanFile.Text = filePath;
                txtResultMd5.Text = AntivirusCore.AntivirusEngine.ComputeMd5(filePath);
                txtResultSha1.Text = ComputeSha1(filePath);
                txtResultSha256.Text = AntivirusCore.AntivirusEngine.ComputeSha256(filePath);

                string threat;
                if (_db.CheckHash(txtResultSha256.Text, out threat) || _db.CheckHash(txtResultMd5.Text, out threat))
                {
                    lblScanVerdict.Text = "🚨 TEHLİKE TESPİT EDİLDİ: " + threat;
                    lblScanVerdict.ForeColor = Color.Red;
                    btnAddScannedHash.Enabled = false;
                }
                else
                {
                    lblScanVerdict.Text = "✅ TEMİZ: Veritabanında bilinen bir tehdit ile eşleşmedi.";
                    lblScanVerdict.ForeColor = Color.DarkGreen;
                    btnAddScannedHash.Enabled = true;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Dosya taranamadı: " + ex.Message, "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void AddScannedToDatabase()
        {
            if (!string.IsNullOrEmpty(txtResultSha256.Text))
            {
                string name = "Suspicious." + Path.GetFileNameWithoutExtension(txtScanFile.Text);
                _db.Add(txtResultSha256.Text, name);
                UpdateListCount();
                AutoSaveDatabase();

                lblScanVerdict.Text = "🚨 Veritabanına Eklendi & Kaydedildi (" + name + ")";
                lblScanVerdict.ForeColor = Color.Red;
                btnAddScannedHash.Enabled = false;
                MessageBox.Show("Dosya hash'i başarıyla veritabanına eklendi ve kalıcı kaydedildi!", "Eklendi & Kaydedildi", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private static string ComputeSha1(string filePath)
        {
            using (var sha = SHA1.Create())
            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
            {
                byte[] hash = sha.ComputeHash(fs);
                var sb = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++) sb.Append(hash[i].ToString("x2"));
                return sb.ToString();
            }
        }

        #endregion

        #region IPC Test

        private void TestIpcLoopback()
        {
            var engine = new AntivirusCore.AntivirusEngine();
            var res = engine.CheckHashViaIpc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            if (res.IsThreat)
            {
                MessageBox.Show("IPC Haberleşmesi Başarılı!\nTest Hash Yanıtı: " + res.ThreatName, "IPC OK", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("IPC Haberleşmesi Çalışıyor.\nYanıt: TEMİZ", "IPC OK", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        #endregion

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            AutoSaveDatabase();

            if (_fileWatcher != null)
            {
                _fileWatcher.EnableRaisingEvents = false;
                _fileWatcher.Dispose();
            }

            if (_clipboardTimer != null)
            {
                _clipboardTimer.Stop();
                _clipboardTimer.Dispose();
            }

            if (_ipcServer != null)
            {
                _ipcServer.Stop();
            }
            base.OnFormClosing(e);
        }
    }
}
