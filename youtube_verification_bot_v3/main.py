# main.py
import os
import sys
import asyncio
import threading
import time
from colorama import init, Fore, Back, Style
from pyfiglet import figlet_format
import questionary
from datetime import datetime

# Colorama başlat
init(autoreset=True)

# Yerel modülleri import et
try:
    from utils.console import Console, Colors
    from utils.logger import Logger
    from utils.config import Config
    from bot.core import YouTubeBot
    from web.app import WebApp
except ImportError as e:
    print(f"❌ Modül import hatası: {e}")
    print("Lütfen gerekli dosyaların doğru konumda olduğundan emin olun!")
    sys.exit(1)

class BotLauncher:
    def __init__(self):
        self.console = Console()
        self.logger = Logger()
        self.config = Config()
        self.bot = None
        self.web_app = None
        self.running = False
        
    def show_banner(self):
        """ASCII Banner göster"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Ana banner
        banner = """
██╗   ██╗ ██████╗ ██╗   ██╗████████╗██╗   ██╗██████╗ ███████╗    ██████╗  ██████╗ ████████╗
╚██╗ ██╔╝██╔═══██╗██║   ██║╚══██╔══╝██║   ██║██╔══██╗██╔════╝    ██╔══██╗██╔═══██╗╚══██╔══╝
 ╚████╔╝ ██║   ██║██║   ██║   ██║   ██║   ██║██████╔╝█████╗      ██████╔╝██║   ██║   ██║   
  ╚██╔╝  ██║   ██║██║   ██║   ██║   ██║   ██║██╔══██╗██╔══╝      ██╔══██╗██║   ██║   ██║   
   ██║   ╚██████╔╝╚██████╔╝   ██║   ╚██████╔╝██████╔╝███████╗    ██████╔╝╚██████╔╝   ██║   
   ╚═╝    ╚═════╝  ╚═════╝    ╚═╝    ╚═════╝ ╚═════╝ ╚══════╝    ╚═════╝  ╚═════╝    ╚═╝   
        """
        
        self.console.print(banner, Colors.CYAN, style='bold')
        self.console.print("=" * 90, Colors.CYAN)
        self.console.print("🎯 YouTube Doğrulama Botu v3.0 - Konsol Launcher", Colors.WHITE, style='bold')
        self.console.print("👥 Geliştirici: AI Assistant & Team", Colors.GRAY)
        self.console.print("🌐 Özellikler: 7/24 Aktif | Web Panel | Gelişmiş OCR | Güvenlik Sistemi", Colors.GREEN)
        self.console.print("=" * 90, Colors.CYAN)
        print()
    
    def main_menu(self):
        """Ana menü"""
        while True:
            try:
                self.console.print("\n🎮 Ana Menü", Colors.CYAN, style='bold')
                
                choice = questionary.select(
                    "Yapmak istediğiniz işlemi seçin:",
                    choices=[
                        "🚀 Botu Başlat (Discord + Web Panel)",
                        "🌐 Sadece Web Paneli Başlat", 
                        "🔧 Bot Ayarlarını Düzenle",
                        "📊 Sistem İstatistiklerini Göster",
                        "📋 Son Logları Görüntüle",
                        "🧪 Sistem Testlerini Çalıştır",
                        "💾 Veritabanı İşlemleri",
                        "🛡️ Güvenlik Kontrolleri",
                        "📦 Railway Deploy Hazırlığı",
                        "❌ Çıkış"
                    ],
                    style=questionary.Style([
                        ('question', 'fg:#ff0066 bold'),
                        ('pointer', 'fg:#ff0066 bold'),
                        ('choice', 'fg:#0099ff'),
                        ('selected', 'fg:#00ff00 bold')
                    ])
                ).ask()
                
                if not choice:  # ESC tuşu
                    break
                    
                if "Botu Başlat" in choice:
                    asyncio.run(self.start_full_system())
                elif "Web Paneli Başlat" in choice:
                    asyncio.run(self.start_web_only())
                elif "Ayarlarını Düzenle" in choice:
                    self.edit_settings()
                elif "İstatistiklerini Göster" in choice:
                    self.show_statistics()
                elif "Logları Görüntüle" in choice:
                    self.show_logs()
                elif "Testlerini Çalıştır" in choice:
                    asyncio.run(self.run_system_tests())
                elif "Veritabanı İşlemleri" in choice:
                    self.database_management()
                elif "Güvenlik Kontrolleri" in choice:
                    self.security_checks()
                elif "Railway Deploy" in choice:
                    self.railway_deploy()
                elif "Çıkış" in choice:
                    self.shutdown()
                    break
                    
            except KeyboardInterrupt:
                self.console.warning("\nÇıkış yapılıyor...")
                self.shutdown()
                break
            except Exception as e:
                self.console.error(f"Menü hatası: {str(e)}")
                time.sleep(2)
    
    async def start_full_system(self):
        """Tam sistem başlatma (Bot + Web Panel)"""
        self.console.info("Tam sistem başlatılıyor...")
        
        # Konfigürasyon kontrolü
        if not self.config.validate():
            self.console.error("❌ Konfigürasyon hatası!")
            self.console.info("Eksik ayarları düzeltmek için '🔧 Bot Ayarlarını Düzenle' seçeneğini kullanın.")
            input("\nDevam etmek için Enter'a basın...")
            return
        
        try:
            # Web panelini arka planda başlat
            self.console.info("Web paneli başlatılıyor...")
            web_thread = threading.Thread(target=self.start_web_background, daemon=True)
            web_thread.start()
            time.sleep(2)  # Web panelin başlaması için bekle
            
            # Discord botunu başlat
            self.console.info("Discord botu başlatılıyor...")
            self.bot = YouTubeBot(self.config)
            
            self.console.success("✅ Sistem başarıyla başlatıldı!")
            self.console.info("🌐 Web Panel: http://localhost:5000")
            self.console.info("🤖 Discord Bot: Aktif")
            self.console.warning("🛑 Durdurmak için Ctrl+C kullanın")
            
            # Botu çalıştır (bu blocking)
            await self.bot.start()
            
        except KeyboardInterrupt:
            self.console.warning("Kullanıcı tarafından durduruldu")
        except Exception as e:
            self.console.error(f"Sistem başlatma hatası: {str(e)}")
        finally:
            await self.cleanup()
    
    async def start_web_only(self):
        """Sadece web paneli başlat"""
        self.console.info("Web paneli başlatılıyor...")
        
        try:
            self.web_app = WebApp(self.config)
            
            self.console.success("✅ Web paneli başlatıldı!")
            self.console.info("🌐 URL: http://localhost:5000")
            self.console.info("👤 Giriş: admin / admin123")
            self.console.warning("🛑 Ana menüye dönmek için Ctrl+C")
            
            # Web uygulamasını çalıştır
            self.web_app.run(
                host=self.config.get('WEB_HOST', 'localhost'),
                port=self.config.get('WEB_PORT', 5000),
                debug=self.config.get('WEB_DEBUG', False)
            )
            
        except KeyboardInterrupt:
            self.console.info("Web paneli durduruldu")
        except Exception as e:
            self.console.error(f"Web paneli hatası: {str(e)}")
    
    def start_web_background(self):
        """Web paneli arka planda başlat"""
        try:
            self.web_app = WebApp(self.config)
            self.web_app.run(
                host='localhost',
                port=5000,
                debug=False
            )
        except Exception as e:
            self.console.error(f"Web panel arka plan hatası: {str(e)}")
    
    def edit_settings(self):
        """Ayarları düzenle"""
        self.console.info("⚙️ Bot Ayarları")
        
        while True:
            setting_choice = questionary.select(
                "Hangi ayarı düzenlemek istiyorsuniz?",
                choices=[
                    "🤖 Discord Bot Token",
                    "📺 YouTube Kanal Bilgileri",
                    "🔍 Doğrulama Kriterleri",
                    "🛡️ Güvenlik Ayarları",
                    "🌐 Web Panel Ayarları",
                    "📁 Tüm Ayarları Görüntüle",
                    "↩️ Ana Menüye Dön"
                ]
            ).ask()
            
            if not setting_choice or "Ana Menüye" in setting_choice:
                break
            elif "Discord Bot Token" in setting_choice:
                self.edit_discord_settings()
            elif "YouTube Kanal" in setting_choice:
                self.edit_youtube_settings()
            elif "Doğrulama Kriterleri" in setting_choice:
                self.edit_verification_settings()
            elif "Güvenlik Ayarları" in setting_choice:
                self.edit_security_settings()
            elif "Web Panel" in setting_choice:
                self.edit_web_settings()
            elif "Tüm Ayarları" in setting_choice:
                self.show_all_settings()
    
    def edit_discord_settings(self):
        """Discord ayarları"""
        self.console.warning("🤖 Discord Bot Ayarları")
        
        current_token = self.config.get('DISCORD_TOKEN', '')
        masked_token = current_token[:10] + "..." if len(current_token) > 10 else "❌ Ayarlanmamış"
        
        self.console.info(f"Mevcut token: {masked_token}")
        
        new_token = questionary.password("Yeni Discord Bot Token (boş bırakırsan değişmez):").ask()
        
        if new_token:
            self.config.set('DISCORD_TOKEN', new_token)
            self.console.success("✅ Discord token güncellendi!")
        
        # Guild ID
        current_guild = self.config.get('GUILD_ID', 0)
        self.console.info(f"Mevcut Guild ID: {current_guild}")
        
        new_guild = questionary.text("Guild (Server) ID:", default=str(current_guild) if current_guild else "").ask()
        if new_guild and new_guild.isdigit():
            self.config.set('GUILD_ID', int(new_guild))
            self.console.success("✅ Guild ID güncellendi!")
        
        # Kanal ID'leri
        channels = [
            ("VERIFICATION_CHANNEL_ID", "Doğrulama Kanalı ID"),
            ("LOG_CHANNEL_ID", "Log Kanalı ID"),
            ("ADMIN_ROLE_ID", "Admin Rol ID"),
            ("SUBSCRIBER_ROLE_ID", "Abone Rol ID")
        ]
        
        for config_key, description in channels:
            current_value = self.config.get(config_key, 0)
            new_value = questionary.text(f"{description}:", default=str(current_value) if current_value else "").ask()
            if new_value and new_value.isdigit():
                self.config.set(config_key, int(new_value))
                self.console.success(f"✅ {description} güncellendi!")
    
    def edit_youtube_settings(self):
        """YouTube ayarları"""
        self.console.warning("📺 YouTube Kanal Ayarları")
        
        current_name = self.config.get('YOUR_CHANNEL_NAME', '')
        new_name = questionary.text("YouTube Kanal Adı:", default=current_name).ask()
        if new_name:
            self.config.set('YOUR_CHANNEL_NAME', new_name)
            self.console.success("✅ Kanal adı güncellendi!")
        
        current_id = self.config.get('YOUR_CHANNEL_ID', '')
        new_id = questionary.text("YouTube Kanal ID (opsiyonel):", default=current_id).ask()
        if new_id:
            self.config.set('YOUR_CHANNEL_ID', new_id)
            self.console.success("✅ Kanal ID güncellendi!")
        
        # YouTube API Key
        current_api = self.config.get('YOUTUBE_API_KEY', '')
        masked_api = current_api[:10] + "..." if len(current_api) > 10 else "❌ Ayarlanmamış"
        self.console.info(f"Mevcut API Key: {masked_api}")
        
        new_api = questionary.password("YouTube API Key (boş bırakırsan değişmez):").ask()
        if new_api:
            self.config.set('YOUTUBE_API_KEY', new_api)
            self.console.success("✅ YouTube API Key güncellendi!")
    
    def edit_verification_settings(self):
        """Doğrulama ayarları"""
        self.console.warning("🔍 Doğrulama Kriterleri")
        
        # Gerekli işlemler
        subscribe_req = questionary.confirm("Abone olma zorunlu?", 
                                          default=self.config.get('SUBSCRIBE_REQUIRED', True)).ask()
        self.config.set('SUBSCRIBE_REQUIRED', subscribe_req)
        
        like_req = questionary.confirm("Beğeni zorunlu?", 
                                     default=self.config.get('LIKE_REQUIRED', True)).ask()
        self.config.set('LIKE_REQUIRED', like_req)
        
        comment_req = questionary.confirm("Yorum zorunlu?", 
                                        default=self.config.get('COMMENT_REQUIRED', True)).ask()
        self.config.set('COMMENT_REQUIRED', comment_req)
        
        # Güven skoru
        min_confidence = questionary.text("Minimum güven skoru (0-100):",
                                         default=str(self.config.get('MIN_CONFIDENCE', 75))).ask()
        if min_confidence.isdigit():
            self.config.set('MIN_CONFIDENCE', int(min_confidence))
        
        self.console.success("✅ Doğrulama kriterleri güncellendi!")
    
    def edit_security_settings(self):
        """Güvenlik ayarları"""
        self.console.warning("🛡️ Güvenlik Ayarları")
        
        # Rate limiting
        rate_requests = questionary.text("Rate limit - İstek sayısı:",
                                        default=str(self.config.get('RATE_LIMIT_REQUESTS', 3))).ask()
        if rate_requests.isdigit():
            self.config.set('RATE_LIMIT_REQUESTS', int(rate_requests))
        
        rate_window = questionary.text("Rate limit - Zaman penceresi (saniye):",
                                      default=str(self.config.get('RATE_LIMIT_WINDOW', 300))).ask()
        if rate_window.isdigit():
            self.config.set('RATE_LIMIT_WINDOW', int(rate_window))
        
        # Duplicate kontrol
        duplicate_check = questionary.confirm("Duplicate resim kontrolü?",
                                            default=self.config.get('DUPLICATE_CHECK', True)).ask()
        self.config.set('DUPLICATE_CHECK', duplicate_check)
        
        self.console.success("✅ Güvenlik ayarları güncellendi!")
    
    def edit_web_settings(self):
        """Web panel ayarları"""
        self.console.warning("🌐 Web Panel Ayarları")
        
        web_port = questionary.text("Web panel portu:",
                                   default=str(self.config.get('WEB_PORT', 5000))).ask()
        if web_port.isdigit():
            self.config.set('WEB_PORT', int(web_port))
        
        web_debug = questionary.confirm("Debug modu?",
                                      default=self.config.get('WEB_DEBUG', False)).ask()
        self.config.set('WEB_DEBUG', web_debug)
        
        self.console.success("✅ Web panel ayarları güncellendi!")
    
    def show_all_settings(self):
        """Tüm ayarları göster"""
        self.console.info("📁 Mevcut Bot Ayarları")
        
        settings_to_show = [
            ('DISCORD_TOKEN', 'Discord Bot Token'),
            ('GUILD_ID', 'Guild (Server) ID'),
            ('VERIFICATION_CHANNEL_ID', 'Doğrulama Kanalı ID'),
            ('YOUR_CHANNEL_NAME', 'YouTube Kanal Adı'),
            ('MIN_CONFIDENCE', 'Minimum Güven Skoru'),
            ('SUBSCRIBE_REQUIRED', 'Abone Olma Zorunlu'),
            ('LIKE_REQUIRED', 'Beğeni Zorunlu'),
            ('COMMENT_REQUIRED', 'Yorum Zorunlu'),
            ('RATE_LIMIT_REQUESTS', 'Rate Limit İstek'),
            ('WEB_PORT', 'Web Panel Port')
        ]
        
        for key, description in settings_to_show:
            value = self.config.get(key, '❌ Ayarlanmamış')
            
            # Token/Key'leri maskele
            if 'TOKEN' in key or 'KEY' in key:
                if isinstance(value, str) and len(value) > 10:
                    value = value[:10] + "..." + value[-4:]
                elif not value or value == '❌ Ayarlanmamış':
                    value = "❌ Ayarlanmamış"
            
            self.console.print(f"  {description}: {value}", Colors.WHITE)
        
        input("\nDevam etmek için Enter'a basın...")
    
    def show_statistics(self):
        """İstatistikleri göster"""
        self.console.info("📊 Sistem İstatistikleri")
        
        try:
            from bot.database import Database
            db = Database()
            stats = db.get_statistics()
            
            self.console.print("\n📈 Veritabanı İstatistikleri", Colors.CYAN, style='bold')
            self.console.success(f"  Toplam Doğrulanmış: {stats.get('total_verified', 0)}")
            self.console.info(f"  Bugün Doğrulanmış: {stats.get('today_verified', 0)}")
            self.console.warning(f"  Bekleyen İstekler: {stats.get('pending_requests', 0)}")
            self.console.error(f"  Reddedilen: {stats.get('rejected', 0)}")
            
            # Sistem bilgileri
            import psutil
            self.console.print("\n💻 Sistem Bilgileri", Colors.CYAN, style='bold')
            self.console.info(f"  CPU Kullanımı: {psutil.cpu_percent()}%")
            self.console.info(f"  RAM Kullanımı: {psutil.virtual_memory().percent}%")
            
            disk = psutil.disk_usage('.')
            disk_percent = (disk.used / disk.total) * 100
            self.console.info(f"  Disk Kullanımı: {disk_percent:.1f}%")
            
        except Exception as e:
            self.console.error(f"İstatistik alma hatası: {str(e)}")
        
        input("\nDevam etmek için Enter'a basın...")
    
    def show_logs(self):
        """Son logları göster"""
        self.console.info("📋 Son Loglar")
        
        try:
            # Log dosyasından son 20 satırı oku
            log_file = "data/logs/bot.log"
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    recent_lines = lines[-20:] if len(lines) > 20 else lines
                    
                    for line in recent_lines:
                        line = line.strip()
                        if 'ERROR' in line:
                            self.console.error(f"  {line}")
                        elif 'WARNING' in line:
                            self.console.warning(f"  {line}")
                        elif 'SUCCESS' in line:
                            self.console.success(f"  {line}")
                        else:
                            self.console.info(f"  {line}")
            else:
                self.console.warning("Log dosyası bulunamadı")
                
        except Exception as e:
            self.console.error(f"Log okuma hatası: {str(e)}")
        
        input("\nDevam etmek için Enter'a basın...")
    
    async def run_system_tests(self):
        """Sistem testleri"""
        self.console.info("🧪 Sistem Testleri Çalıştırılıyor...")
        
        tests = [
            ("📊 Veritabanı Bağlantısı", self.test_database),
            ("⚙️ Konfigürasyon", self.test_config),
            ("🔤 OCR Sistemi", self.test_ocr),
            ("🛡️ Güvenlik Sistemi", self.test_security),
            ("🧠 Resim Hafızası", self.test_image_memory)
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            self.console.info(f"Test ediliyor: {test_name}")
            
            try:
                result = await test_func()
                if result:
                    self.console.success(f"✅ {test_name} - BAŞARILI")
                    passed += 1
                else:
                    self.console.error(f"❌ {test_name} - BAŞARISIZ")
            except Exception as e:
                self.console.error(f"❌ {test_name} - HATA: {str(e)}")
        
        self.console.print(f"\n📊 Test Sonucu: {passed}/{total} başarılı", Colors.CYAN, style='bold')
        
        if passed == total:
            self.console.success("🎉 Tüm testler başarılı!")
        else:
            self.console.warning(f"⚠️ {total - passed} test başarısız. Ayarları kontrol edin.")
        
        input("\nDevam etmek için Enter'a basın...")
    
    async def test_database(self):
        """Veritabanı testi"""
        try:
            from bot.database import Database
            db = Database()
            return db.test_connection()
        except:
            return False
    
    async def test_config(self):
        """Konfigürasyon testi"""
        return self.config.validate()
    
    async def test_ocr(self):
        """OCR testi"""
        try:
            from bot.ocr_engine import OCREngine
            ocr = OCREngine(self.config)
            return await ocr.test_connection()
        except:
            return False
    
    async def test_security(self):
        """Güvenlik testi"""
        try:
            from bot.security import SecurityManager
            security = SecurityManager(self.config)
            return security.test_security_system()
        except:
            return False
    
    async def test_image_memory(self):
        """Resim hafızası testi"""
        try:
            from bot.image_memory import ImageMemory
            memory = ImageMemory()
            return memory.test_system()
        except:
            return False
    
    def database_management(self):
        """Veritabanı yönetimi"""
        self.console.info("💾 Veritabanı İşlemleri")
        
        db_choice = questionary.select(
            "Hangi işlemi yapmak istiyorsunuz?",
            choices=[
                "📊 Veritabanı İstatistikleri",
                "💾 Yedek Oluştur",
                "📥 Yedekten Geri Yükle",
                "🧹 Eski Kayıtları Temizle",
                "⚠️ Veritabanını Sıfırla",
                "↩️ Geri Dön"
            ]
        ).ask()
        
        if not db_choice or "Geri Dön" in db_choice:
            return
        
        try:
            from bot.database import Database
            db = Database()
            
            if "İstatistikleri" in db_choice:
                stats = db.get_statistics()
                self.console.success(f"Toplam doğrulanmış: {stats.get('total_verified', 0)}")
                self.console.info(f"Bekleyen istekler: {stats.get('pending_requests', 0)}")
                
            elif "Yedek Oluştur" in db_choice:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = f"data/backups/backup_{timestamp}"
                if db.backup_database(backup_path):
                    self.console.success(f"✅ Yedek oluşturuldu: {backup_path}")
                else:
                    self.console.error("❌ Yedekleme başarısız!")
                    
            elif "Temizle" in db_choice:
                days = questionary.text("Kaç günden eski kayıtlar temizlensin?", default="30").ask()
                if days.isdigit():
                    db.cleanup_old_pending(int(days))
                    self.console.success("✅ Eski kayıtlar temizlendi!")
                    
            elif "Sıfırla" in db_choice:
                if questionary.confirm("⚠️ TÜM VERİTABANI SİLİNECEK! Emin misiniz?", default=False).ask():
                    if db.clean_all():
                        self.console.success("✅ Veritabanı sıfırlandı!")
                    else:
                        self.console.error("❌ Sıfırlama başarısız!")
                        
        except Exception as e:
            self.console.error(f"Veritabanı işlemi hatası: {str(e)}")
        
        input("\nDevam etmek için Enter'a basın...")
    
    def security_checks(self):
        """Güvenlik kontrolleri"""
        self.console.info("🛡️ Güvenlik Kontrolleri")
        
        try:
            from bot.security import SecurityManager
            security = SecurityManager(self.config)
            
            stats = security.get_security_statistics()
            
            self.console.print("\n🔍 Güvenlik İstatistikleri", Colors.CYAN, style='bold')
            self.console.info(f"  Toplam güvenlik olayları: {stats.get('total_security_events', 0)}")
            self.console.warning(f"  Son 24 saatteki olaylar: {stats.get('events_last_24h', 0)}")
            self.console.error(f"  Şüpheli kullanıcılar: {stats.get('suspicious_users', {}).get('total', 0)}")
            
            # Blacklist bilgileri
            blacklist_sizes = stats.get('blacklist_sizes', {})
            total_blacklist = sum(blacklist_sizes.values())
            self.console.info(f"  Blacklist boyutu: {total_blacklist}")
            
        except Exception as e:
            self.console.error(f"Güvenlik kontrolü hatası: {str(e)}")
        
        input("\nDevam etmek için Enter'a basın...")
    
    def railway_deploy(self):
        """Railway deploy hazırlığı"""
        self.console.info("📦 Railway Deploy Hazırlığı")
        
        # Gerekli dosyaları oluştur
        self.create_railway_files()
        
        self.console.success("✅ Railway dosyaları oluşturuldu!")
        self.console.info("\n📋 Deploy Adımları:")
        self.console.print("1. Railway hesabı oluşturun: https://railway.app", Colors.WHITE)
        self.console.print("2. GitHub reposunu Railway'e bağlayın", Colors.WHITE)
        self.console.print("3. Environment variables'ları ayarlayın", Colors.WHITE)
        self.console.print("4. Deploy edin!", Colors.WHITE)
        
        self.console.print("\n🔧 Gerekli Environment Variables:", Colors.YELLOW)
        env_vars = [
            "DISCORD_TOKEN", "GUILD_ID", "VERIFICATION_CHANNEL_ID",
            "ADMIN_ROLE_ID", "SUBSCRIBER_ROLE_ID", "LOG_CHANNEL_ID",
            "YOUR_CHANNEL_NAME", "YOUR_CHANNEL_ID"
        ]
        
        for var in env_vars:
            value = self.config.get(var, "❌ Ayarlanmamış")
            if 'TOKEN' in var:
                value = "your_token_here"
            self.console.print(f"  {var}={value}", Colors.WHITE)
        
        input("\nDevam etmek için Enter'a basın...")
    
    def create_railway_files(self):
        """Railway için gerekli dosyaları oluştur"""
        # Procfile
        with open('Procfile', 'w') as f:
            f.write('web: python main.py --railway\n')
        
        # railway.json
        railway_config = {
            "build": {
                "builder": "NIXPACKS"
            },
            "deploy": {
                "startCommand": "python main.py --railway",
                "restartPolicyType": "ON_FAILURE"
            }
        }
        
        with open('railway.json', 'w') as f:
            import json
            json.dump(railway_config, f, indent=2)
        
        # .env.example
        self.config.create_env_template()
    
    async def cleanup(self):
        """Temizlik işlemleri"""
        if self.bot:
            try:
                await self.bot.stop()
            except:
                pass
        self.console.info("Temizlik tamamlandı")
    
    def shutdown(self):
        """Sistemi kapat"""
        self.console.warning("Sistem kapatılıyor...")
        self.console.success("Güle güle! 👋")
        sys.exit(0)

def main():
    """Ana fonksiyon"""
    try:
        launcher = BotLauncher()
        launcher.show_banner()
        
        # Railway modunda mı?
        if len(sys.argv) > 1 and sys.argv[1] == '--railway':
            # Railway için sadece bot başlat
            launcher.console.info("Railway modunda başlatılıyor...")
            asyncio.run(launcher.start_full_system())
        else:
            # Normal modda konsol menü
            launcher.main_menu()
            
    except KeyboardInterrupt:
        print("\n👋 Güle güle!")
    except Exception as e:
        print(f"❌ Kritik hata: {str(e)}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()