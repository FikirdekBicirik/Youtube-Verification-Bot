# web/app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_socketio import SocketIO, emit
import json
import os
from datetime import datetime, timedelta
from functools import wraps
import secrets
import hashlib
from typing import Dict, List, Optional
import asyncio
import threading

from utils.logger import Logger
from utils.config import Config
from bot.database import Database
from bot.image_memory import ImageMemory
from bot.security import SecurityManager

class WebApp:
    """Flask Web Panel Uygulaması"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger()
        self.database = Database()
        self.image_memory = ImageMemory()
        self.security = SecurityManager(config)
        
        # Flask app oluştur
        self.app = Flask(__name__, 
                        template_folder='templates',
                        static_folder='static')
        
        # Güvenlik ayarları
        self.app.config['SECRET_KEY'] = config.get('SECRET_KEY', secrets.token_hex(32))
        self.app.config['WTF_CSRF_ENABLED'] = True
        self.app.config['SESSION_COOKIE_SECURE'] = True
        self.app.config['SESSION_COOKIE_HTTPONLY'] = True
        self.app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
        
        # SocketIO (gerçek zamanlı iletişim)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Admin kimlik bilgileri (basit auth)
        self.admin_credentials = {
            'admin': self.hash_password('admin123'),  # Değiştirin!
            'moderator': self.hash_password('mod123')  # Değiştirin!
        }
        
        self.setup_routes()
        self.setup_socketio_events()
        self.setup_template_functions()
        
        # Background tasks
        self.start_background_tasks()
    
    def hash_password(self, password: str) -> str:
        """Şifre hash'le"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Şifre doğrula"""
        return self.hash_password(password) == hashed
    
    def login_required(self, f):
        """Login gerektiren decorator"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'logged_in' not in session or not session['logged_in']:
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    
    def admin_required(self, f):
        """Admin gerektiren decorator"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session or session['user_role'] != 'admin':
                flash('Admin yetkisi gerekli!', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    
    def setup_routes(self):
        """URL route'larını ayarla"""
        
        @self.app.route('/')
        def index():
            """Ana sayfa"""
            if 'logged_in' in session and session['logged_in']:
                return redirect(url_for('dashboard'))
            return redirect(url_for('login'))
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            """Giriş sayfası"""
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                
                if username in self.admin_credentials:
                    if self.verify_password(password, self.admin_credentials[username]):
                        session['logged_in'] = True
                        session['username'] = username
                        session['user_role'] = 'admin' if username == 'admin' else 'moderator'
                        session['login_time'] = datetime.now().isoformat()
                        
                        self.logger.info(f"Web panel girişi: {username}")
                        flash(f'Hoş geldiniz, {username}!', 'success')
                        return redirect(url_for('dashboard'))
                    else:
                        flash('Hatalı şifre!', 'error')
                else:
                    flash('Kullanıcı bulunamadı!', 'error')
            
            return render_template('login.html')
        
        @self.app.route('/logout')
        def logout():
            """Çıkış"""
            username = session.get('username', 'Unknown')
            session.clear()
            self.logger.info(f"Web panel çıkışı: {username}")
            flash('Başarıyla çıkış yapıldı.', 'info')
            return redirect(url_for('login'))
        
        @self.app.route('/dashboard')
        @self.login_required
        def dashboard():
            """Ana panel"""
            try:
                # Temel istatistikler
                stats = self.database.get_statistics()
                security_stats = self.security.get_security_statistics()
                memory_info = self.image_memory.get_memory_info()
                
                # Son 24 saatin verileri
                recent_logs = self.logger.get_logs('Son 50 log', 20)
                
                return render_template('dashboard.html',
                    stats=stats,
                    security_stats=security_stats,
                    memory_info=memory_info,
                    recent_logs=recent_logs,
                    current_time=datetime.now()
                )
            except Exception as e:
                self.logger.error(f"Dashboard hatası: {str(e)}")
                flash('Dashboard yüklenirken hata oluştu!', 'error')
                return render_template('dashboard.html', stats={}, security_stats={}, memory_info={})
        
        @self.app.route('/users')
        @self.login_required
        def users():
            """Kullanıcı yönetimi"""
            try:
                verified_users = self.database.get_all_verified_users()
                suspicious_users = self.security.load_json(self.security.suspicious_users_file, {})
                
                # Kullanıcı listesini hazırla
                user_list = []
                for user_id, user_data in verified_users.items():
                    suspicious_info = suspicious_users.get(user_id, {})
                    
                    user_list.append({
                        'user_id': user_id,
                        'username': user_data.get('username', 'Unknown'),
                        'verified_at': user_data.get('verified_at'),
                        'verification_count': user_data.get('verification_count', 1),
                        'security_score': user_data.get('security_score', 100),
                        'is_suspicious': bool(suspicious_info),
                        'risk_level': suspicious_info.get('status', 'none'),
                        'last_activity': user_data.get('last_updated', user_data.get('verified_at'))
                    })
                
                # Son aktiviteye göre sırala
                user_list.sort(key=lambda x: x['last_activity'] or '', reverse=True)
                
                return render_template('users.html', users=user_list)
                
            except Exception as e:
                self.logger.error(f"Kullanıcı listesi hatası: {str(e)}")
                flash('Kullanıcı listesi yüklenirken hata oluştu!', 'error')
                return render_template('users.html', users=[])
        
        @self.app.route('/logs')
        @self.login_required
        def logs():
            """Log görüntüleme"""
            try:
                log_type = request.args.get('type', 'Son 50 log')
                limit = int(request.args.get('limit', 50))
                
                logs = self.logger.get_logs(log_type, limit)
                log_stats = self.logger.get_statistics()
                
                return render_template('logs.html', 
                    logs=logs, 
                    log_stats=log_stats,
                    current_filter=log_type
                )
                
            except Exception as e:
                self.logger.error(f"Log görüntüleme hatası: {str(e)}")
                flash('Loglar yüklenirken hata oluştu!', 'error')
                return render_template('logs.html', logs=[], log_stats={})
        
        @self.app.route('/security')
        @self.login_required
        def security():
            """Güvenlik paneli"""
            try:
                security_stats = self.security.get_security_statistics()
                security_events = self.security.load_json(self.security.security_events_file, [])
                
                # Son 100 güvenlik olayı
                recent_events = sorted(security_events, 
                                     key=lambda x: x.get('timestamp', ''), 
                                     reverse=True)[:100]
                
                suspicious_users = self.security.load_json(self.security.suspicious_users_file, {})
                blacklist = self.security.load_json(self.security.blacklist_file, {})
                
                return render_template('security.html',
                    security_stats=security_stats,
                    recent_events=recent_events,
                    suspicious_users=suspicious_users,
                    blacklist=blacklist
                )
                
            except Exception as e:
                self.logger.error(f"Güvenlik paneli hatası: {str(e)}")
                flash('Güvenlik paneli yüklenirken hata oluştu!', 'error')
                return render_template('security.html', 
                    security_stats={}, recent_events=[], 
                    suspicious_users={}, blacklist={})
        
        @self.app.route('/settings')
        @self.admin_required
        def settings():
            """Ayarlar paneli"""
            try:
                # Mevcut konfigürasyonu al
                current_config = {
                    'SUBSCRIBE_REQUIRED': self.config.get('SUBSCRIBE_REQUIRED'),
                    'LIKE_REQUIRED': self.config.get('LIKE_REQUIRED'),
                    'COMMENT_REQUIRED': self.config.get('COMMENT_REQUIRED'),
                    'MIN_CONFIDENCE': self.config.get('MIN_CONFIDENCE'),
                    'AUTO_VERIFICATION': self.config.get('AUTO_VERIFICATION'),
                    'MANUAL_REVIEW_THRESHOLD': self.config.get('MANUAL_REVIEW_THRESHOLD'),
                    'AUTO_APPROVE_THRESHOLD': self.config.get('AUTO_APPROVE_THRESHOLD'),
                    'RATE_LIMIT_REQUESTS': self.config.get('RATE_LIMIT_REQUESTS'),
                    'RATE_LIMIT_WINDOW': self.config.get('RATE_LIMIT_WINDOW'),
                    'YOUR_CHANNEL_NAME': self.config.get('YOUR_CHANNEL_NAME'),
                    'ENABLE_IMAGE_MEMORY': self.config.get('ENABLE_IMAGE_MEMORY'),
                    'DUPLICATE_CHECK': self.config.get('DUPLICATE_CHECK')
                }
                
                return render_template('settings.html', config=current_config)
                
            except Exception as e:
                self.logger.error(f"Ayarlar paneli hatası: {str(e)}")
                flash('Ayarlar paneli yüklenirken hata oluştu!', 'error')
                return render_template('settings.html', config={})
        
        # API Endpoints
        @self.app.route('/api/stats')
        @self.login_required
        def api_stats():
            """API: İstatistikler"""
            try:
                stats = self.database.get_statistics()
                security_stats = self.security.get_security_statistics()
                
                return jsonify({
                    'success': True,
                    'data': {
                        'database': stats,
                        'security': security_stats,
                        'timestamp': datetime.now().isoformat()
                    }
                })
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/user/<int:user_id>')
        @self.login_required
        def api_user_info(user_id):
            """API: Kullanıcı bilgisi"""
            try:
                user_data = self.database.get_user_data(user_id)
                suspicious_info = self.security.is_user_suspicious(user_id)
                image_history = self.image_memory.get_user_image_history(user_id)
                
                return jsonify({
                    'success': True,
                    'data': {
                        'user_data': user_data,
                        'suspicious_info': suspicious_info,
                        'image_history': image_history
                    }
                })
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/user/<int:user_id>/verify', methods=['POST'])
        @self.admin_required
        def api_manual_verify(user_id):
            """API: Manuel doğrulama"""
            try:
                username = request.json.get('username', f'User_{user_id}')
                admin_user = session.get('username')
                
                success = self.database.add_verified_user(
                    user_id, username, manual=True, 
                    admin_id=0, confidence=100
                )
                
                if success:
                    self.logger.admin_action(
                        0, admin_user, 'manuel_dogrulama', 
                        username, {'user_id': user_id}
                    )
                    
                    # Real-time bildirim gönder
                    self.socketio.emit('user_verified', {
                        'user_id': user_id,
                        'username': username,
                        'admin': admin_user
                    })
                    
                    return jsonify({'success': True, 'message': 'Kullanıcı doğrulandı'})
                else:
                    return jsonify({'success': False, 'error': 'Doğrulama başarısız'})
                    
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/user/<int:user_id>/unverify', methods=['POST'])
        @self.admin_required
        def api_unverify(user_id):
            """API: Doğrulamayı kaldır"""
            try:
                admin_user = session.get('username')
                
                success = self.database.remove_verified_user(user_id)
                
                if success:
                    self.logger.admin_action(
                        0, admin_user, 'dogrulama_kaldir',
                        f'User_{user_id}', {'user_id': user_id}
                    )
                    
                    # Real-time bildirim gönder
                    self.socketio.emit('user_unverified', {
                        'user_id': user_id,
                        'admin': admin_user
                    })
                    
                    return jsonify({'success': True, 'message': 'Doğrulama kaldırıldı'})
                else:
                    return jsonify({'success': False, 'error': 'İşlem başarısız'})
                    
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/security/blacklist', methods=['POST'])
        @self.admin_required
        def api_add_blacklist():
            """API: Blacklist'e ekle"""
            try:
                item_type = request.json.get('type')
                value = request.json.get('value')
                reason = request.json.get('reason', 'Web panel üzerinden eklendi')
                
                self.security.add_to_blacklist(item_type, value, reason)
                
                return jsonify({'success': True, 'message': 'Blacklist\'e eklendi'})
                
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/security/blacklist', methods=['DELETE'])
        @self.admin_required
        def api_remove_blacklist():
            """API: Blacklist'ten kaldır"""
            try:
                item_type = request.json.get('type')
                value = request.json.get('value')
                
                self.security.remove_from_blacklist(item_type, value)
                
                return jsonify({'success': True, 'message': 'Blacklist\'ten kaldırıldı'})
                
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/config/update', methods=['POST'])
        @self.admin_required
        def api_update_config():
            """API: Konfigürasyon güncelle"""
            try:
                config_data = request.json
                admin_user = session.get('username')
                
                # Güvenli alanları güncelle
                safe_fields = [
                    'SUBSCRIBE_REQUIRED', 'LIKE_REQUIRED', 'COMMENT_REQUIRED',
                    'MIN_CONFIDENCE', 'AUTO_VERIFICATION', 'MANUAL_REVIEW_THRESHOLD',
                    'AUTO_APPROVE_THRESHOLD', 'RATE_LIMIT_REQUESTS', 'RATE_LIMIT_WINDOW',
                    'YOUR_CHANNEL_NAME', 'ENABLE_IMAGE_MEMORY', 'DUPLICATE_CHECK'
                ]
                
                updated_fields = []
                for field in safe_fields:
                    if field in config_data:
                        old_value = self.config.get(field)
                        new_value = config_data[field]
                        
                        # Tip kontrolü
                        if isinstance(old_value, bool):
                            new_value = bool(new_value)
                        elif isinstance(old_value, int):
                            new_value = int(new_value)
                        elif isinstance(old_value, str):
                            new_value = str(new_value)
                        
                        self.config.set(field, new_value)
                        updated_fields.append(f"{field}: {old_value} -> {new_value}")
                
                # Admin log
                self.logger.admin_action(
                    0, admin_user, 'config_update',
                    'system', {'updated_fields': updated_fields}
                )
                
                # Real-time bildirim
                self.socketio.emit('config_updated', {
                    'admin': admin_user,
                    'fields': updated_fields
                })
                
                return jsonify({
                    'success': True, 
                    'message': f'{len(updated_fields)} alan güncellendi',
                    'updated_fields': updated_fields
                })
                
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        @self.app.route('/api/logs/export')
        @self.admin_required
        def api_export_logs():
            """API: Log dışa aktarma"""
            try:
                log_type = request.args.get('type', 'all')
                days = int(request.args.get('days', 7))
                
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"logs_export_{timestamp}.json"
                
                # Export işlemi (basitleştirilmiş)
                logs = self.logger.get_logs(log_type, limit=10000)
                
                return jsonify({
                    'success': True,
                    'download_url': f'/download/logs/{filename}',
                    'log_count': len(logs)
                })
                
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
    
    def setup_socketio_events(self):
        """SocketIO event'lerini ayarla"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Bağlantı kuruldu"""
            if 'logged_in' not in session or not session['logged_in']:
                return False  # Bağlantıyı reddet
            
            emit('connected', {'message': 'Web panel\'e bağlandınız'})
            
            # Gerçek zamanlı istatistikleri gönder
            self.send_realtime_stats()
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Bağlantı kesildi"""
            pass
        
        @self.socketio.on('request_stats')
        def handle_stats_request():
            """İstatistik talebi"""
            if 'logged_in' in session and session['logged_in']:
                self.send_realtime_stats()
        
        @self.socketio.on('request_logs')
        def handle_logs_request(data):
            """Log talebi"""
            if 'logged_in' in session and session['logged_in']:
                log_type = data.get('type', 'Son 50 log')
                limit = data.get('limit', 20)
                
                logs = self.logger.get_logs(log_type, limit)
                emit('logs_update', {'logs': logs})
    
    def send_realtime_stats(self):
        """Gerçek zamanlı istatistikleri gönder"""
        try:
            stats = self.database.get_statistics()
            security_stats = self.security.get_security_statistics()
            
            self.socketio.emit('stats_update', {
                'database': stats,
                'security': security_stats,
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            self.logger.error(f"Real-time stats hatası: {str(e)}")
    
    def setup_template_functions(self):
        """Template fonksiyonlarını ayarla"""
        
        @self.app.template_filter('datetime')
        def datetime_filter(value):
            """Datetime formatı"""
            if isinstance(value, str):
                try:
                    dt = datetime.fromisoformat(value)
                    return dt.strftime('%d.%m.%Y %H:%M')
                except:
                    return value
            return value
        
        @self.app.template_filter('timeago')
        def timeago_filter(value):
            """Zaman farkı"""
            if isinstance(value, str):
                try:
                    dt = datetime.fromisoformat(value)
                    now = datetime.now()
                    diff = now - dt
                    
                    if diff.days > 0:
                        return f"{diff.days} gün önce"
                    elif diff.seconds > 3600:
                        hours = diff.seconds // 3600
                        return f"{hours} saat önce"
                    elif diff.seconds > 60:
                        minutes = diff.seconds // 60
                        return f"{minutes} dakika önce"
                    else:
                        return "Az önce"
                except:
                    return value
            return value
        
        @self.app.template_filter('percentage')
        def percentage_filter(value, total):
            """Yüzde hesapla"""
            try:
                if total > 0:
                    return f"{(value / total * 100):.1f}%"
                return "0%"
            except:
                return "0%"
        
        @self.app.context_processor
        def inject_globals():
            """Global template değişkenleri"""
            return {
                'current_time': datetime.now(),
                'app_version': '3.0.0',
                'user_role': session.get('user_role', 'guest'),
                'username': session.get('username', 'Anonymous')
            }
    
    def start_background_tasks(self):
        """Arka plan görevlerini başlat"""
        def background_loop():
            """Arka plan döngüsü"""
            while True:
                try:
                    # Her 30 saniyede bir real-time stats gönder
                    self.socketio.sleep(30)
                    
                    if hasattr(self.socketio, 'server') and self.socketio.server:
                        self.send_realtime_stats()
                        
                        # Yeni logları gönder
                        recent_logs = self.logger.get_logs('Son 50 log', 5)
                        self.socketio.emit('new_logs', {'logs': recent_logs})
                        
                except Exception as e:
                    self.logger.error(f"Background task hatası: {str(e)}")
                    self.socketio.sleep(60)  # Hata durumunda 1 dakika bekle
        
        # Background thread başlat
        background_thread = threading.Thread(target=background_loop, daemon=True)
        background_thread.start()
    
    def run(self, host='localhost', port=5000, debug=False):
        """Web uygulamasını çalıştır"""
        try:
            self.logger.info(f"Web paneli başlatılıyor: http://{host}:{port}")
            
            # Template klasörünü kontrol et
            if not os.path.exists(self.app.template_folder):
                self.logger.warning("Template klasörü bulunamadı, basit template'ler oluşturuluyor")
                self.create_basic_templates()
            
            # Static klasörünü kontrol et
            if not os.path.exists(self.app.static_folder):
                self.logger.warning("Static klasörü bulunamadı, temel dosyalar oluşturuluyor")
                self.create_basic_static_files()
            
            # SocketIO ile çalıştır
            self.socketio.run(
                self.app,
                host=host,
                port=port,
                debug=debug,
                use_reloader=False  # Threading sorunları önlemek için
            )
            
        except Exception as e:
            self.logger.error(f"Web panel başlatma hatası: {str(e)}")
            raise
    
    def create_basic_templates(self):
        """Temel template'leri oluştur"""
        os.makedirs(self.app.template_folder, exist_ok=True)
        
        # Base template
        base_template = '''<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}YouTube Doğrulama Botu{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.socket.io/4.5.0/socket.io.min.js"></script>
</head>
<body>
    {% block content %}{% endblock %}
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>'''
        
        with open(os.path.join(self.app.template_folder, 'base.html'), 'w', encoding='utf-8') as f:
            f.write(base_template)
        
        # Login template
        login_template = '''{% extends "base.html" %}

{% block title %}Giriş - YouTube Doğrulama Botu{% endblock %}

{% block content %}
<div class="container-fluid vh-100 d-flex align-items-center justify-content-center bg-primary">
    <div class="card shadow-lg" style="width: 400px;">
        <div class="card-header bg-dark text-white text-center">
            <h4><i class="fab fa-youtube text-danger"></i> Bot Paneli</h4>
        </div>
        <div class="card-body">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-dismissible fade show">
                            {{ message }}
                            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <form method="POST">
                <div class="mb-3">
                    <label for="username" class="form-label">Kullanıcı Adı</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Şifre</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary w-100">Giriş Yap</button>
            </form>
        </div>
    </div>
</div>
{% endblock %}'''
        
        with open(os.path.join(self.app.template_folder, 'login.html'), 'w', encoding='utf-8') as f:
            f.write(login_template)
        
        self.logger.info("Temel template'ler oluşturuldu")
    
    def create_basic_static_files(self):
        """Temel static dosyaları oluştur"""
        os.makedirs(self.app.static_folder, exist_ok=True)
        
        # Basit CSS
        css_content = '''
/* YouTube Bot Panel CSS */
.sidebar {
    background: #2c3e50;
    min-height: 100vh;
}

.card-stats {
    transition: transform 0.2s;
}

.card-stats:hover {
    transform: translateY(-2px);
}

.log-entry {
    font-family: monospace;
    font-size: 0.9em;
}

.realtime-indicator {
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.5; }
    100% { opacity: 1; }
}
'''
        
        os.makedirs(os.path.join(self.app.static_folder, 'css'), exist_ok=True)
        with open(os.path.join(self.app.static_folder, 'css', 'style.css'), 'w', encoding='utf-8') as f:
            f.write(css_content)
        
        self.logger.info("Temel static dosyalar oluşturuldu")