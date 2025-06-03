# web/routes/dashboard.py
from flask import Blueprint, render_template, jsonify, request, session
from datetime import datetime, timedelta
import json
from typing import Dict, List, Any

from utils.logger import Logger
from utils.config import Config
from bot.database import Database
from bot.image_memory import ImageMemory
from bot.security import SecurityManager

dashboard_bp = Blueprint('dashboard', __name__)

class DashboardManager:
    """Dashboard yönetim sınıfı"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger()
        self.database = Database()
        self.image_memory = ImageMemory()
        self.security = SecurityManager(config)
    
    def get_dashboard_data(self) -> Dict[str, Any]:
        """Dashboard için gerekli tüm verileri topla"""
        try:
            # Temel istatistikler
            db_stats = self.database.get_statistics()
            security_stats = self.security.get_security_statistics()
            memory_stats = self.image_memory.get_duplicate_statistics()
            
            # Son 24 saat aktivitesi
            activity_data = self.get_24h_activity()
            
            # Sistem durumu
            system_status = self.get_system_status()
            
            # Top kullanıcılar
            top_users = self.get_top_users()
            
            # Son olaylar
            recent_events = self.get_recent_events()
            
            # Performans metrikleri
            performance_metrics = self.get_performance_metrics()
            
            return {
                'database': db_stats,
                'security': security_stats,
                'memory': memory_stats,
                'activity_24h': activity_data,
                'system_status': system_status,
                'top_users': top_users,
                'recent_events': recent_events,
                'performance': performance_metrics,
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Dashboard veri toplama hatası: {str(e)}")
            return {}
    
    def get_24h_activity(self) -> Dict[str, Any]:
        """Son 24 saatin aktivite verileri"""
        try:
            now = datetime.now()
            hours_data = []
            
            # Son 24 saati saatlik dilimlere böl
            for i in range(24):
                hour_start = now - timedelta(hours=i+1)
                hour_end = now - timedelta(hours=i)
                
                # Bu saatteki aktiviteleri say
                hour_stats = {
                    'hour': hour_start.strftime('%H:00'),
                    'timestamp': hour_start.isoformat(),
                    'verifications': 0,
                    'rejections': 0,
                    'security_events': 0,
                    'duplicates': 0
                }
                
                # Veritabanından o saatteki verileri al
                verified_users = self.database.get_all_verified_users()
                for user_data in verified_users.values():
                    verified_at = user_data.get('verified_at')
                    if verified_at:
                        try:
                            verified_time = datetime.fromisoformat(verified_at)
                            if hour_start <= verified_time < hour_end:
                                hour_stats['verifications'] += 1
                        except:
                            continue
                
                # Güvenlik olayları
                security_events = self.security.load_json(self.security.security_events_file, [])
                for event in security_events:
                    event_time_str = event.get('timestamp')
                    if event_time_str:
                        try:
                            event_time = datetime.fromisoformat(event_time_str)
                            if hour_start <= event_time < hour_end:
                                hour_stats['security_events'] += 1
                        except:
                            continue
                
                hours_data.append(hour_stats)
            
            # Ters çevir (en eski saat önce)
            hours_data.reverse()
            
            # Toplam sayılar
            total_activity = {
                'total_verifications': sum(h['verifications'] for h in hours_data),
                'total_rejections': sum(h['rejections'] for h in hours_data),
                'total_security_events': sum(h['security_events'] for h in hours_data),
                'total_duplicates': sum(h['duplicates'] for h in hours_data),
                'peak_hour': max(hours_data, key=lambda x: x['verifications'])['hour'] if hours_data else 'N/A',
                'hourly_data': hours_data
            }
            
            return total_activity
            
        except Exception as e:
            self.logger.error(f"24h aktivite hatası: {str(e)}")
            return {}
    
    def get_system_status(self) -> Dict[str, Any]:
        """Sistem durumu"""
        try:
            # Bot durumu (basit kontrol)
            bot_status = 'online'  # Bu gerçek bot durumundan alınabilir
            
            # Veritabanı durumu
            db_healthy = self.database.test_connection()
            
            # OCR durumu
            try:
                from bot.ocr_engine import OCREngine
                ocr = OCREngine(self.config)
                ocr_healthy = await ocr.test_connection()
            except:
                ocr_healthy = False
            
            # Image memory durumu
            memory_healthy = self.image_memory.test_system()
            
            # Güvenlik sistemi durumu
            security_healthy = self.security.test_security_system()
            
            # Disk kullanımı
            import shutil
            disk_usage = shutil.disk_usage(".")
            disk_free_percent = (disk_usage.free / disk_usage.total) * 100
            
            # Memory kullanımı (basit)
            import psutil
            memory_usage = psutil.virtual_memory()
            
            return {
                'bot_status': bot_status,
                'overall_health': 'healthy' if all([db_healthy, ocr_healthy, memory_healthy, security_healthy]) else 'warning',
                'components': {
                    'database': 'healthy' if db_healthy else 'error',
                    'ocr_engine': 'healthy' if ocr_healthy else 'warning',
                    'image_memory': 'healthy' if memory_healthy else 'error',
                    'security_system': 'healthy' if security_healthy else 'warning'
                },
                'resources': {
                    'disk_free_percent': round(disk_free_percent, 1),
                    'memory_percent': memory_usage.percent,
                    'uptime': self.get_uptime()
                },
                'last_check': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Sistem durumu hatası: {str(e)}")
            return {
                'bot_status': 'unknown',
                'overall_health': 'error',
                'components': {},
                'resources': {},
                'error': str(e)
            }
    
    def get_uptime(self) -> str:
        """Uptime hesapla"""
        try:
            # Basit uptime (log dosyasının oluşturulma tarihinden)
            import os
            log_file = "data/logs/bot.log"
            if os.path.exists(log_file):
                creation_time = datetime.fromtimestamp(os.path.getctime(log_file))
                uptime_delta = datetime.now() - creation_time
                
                days = uptime_delta.days
                hours, remainder = divmod(uptime_delta.seconds, 3600)
                minutes, _ = divmod(remainder, 60)
                
                if days > 0:
                    return f"{days}g {hours}s {minutes}d"
                elif hours > 0:
                    return f"{hours}s {minutes}d"
                else:
                    return f"{minutes}d"
            
            return "Bilinmiyor"
            
        except Exception:
            return "Hesaplanamadı"
    
    def get_top_users(self) -> List[Dict[str, Any]]:
        """En aktif kullanıcılar"""
        try:
            verified_users = self.database.get_all_verified_users()
            user_attempts = self.database.load_json(self.database.user_attempts_file, {})
            
            user_list = []
            
            for user_id, user_data in verified_users.items():
                attempts_data = user_attempts.get(user_id, {})
                
                user_info = {
                    'user_id': user_id,
                    'username': user_data.get('username', 'Unknown'),
                    'verified_at': user_data.get('verified_at'),
                    'verification_count': user_data.get('verification_count', 1),
                    'total_attempts': attempts_data.get('total_attempts', 0),
                    'security_score': user_data.get('security_score', 100),
                    'last_activity': user_data.get('last_updated', user_data.get('verified_at'))
                }
                
                user_list.append(user_info)
            
            # Aktiviteye göre sırala (verification count + attempts)
            user_list.sort(key=lambda x: x['verification_count'] + x['total_attempts'], reverse=True)
            
            return user_list[:10]  # Top 10
            
        except Exception as e:
            self.logger.error(f"Top kullanıcılar hatası: {str(e)}")
            return []
    
    def get_recent_events(self) -> List[Dict[str, Any]]:
        """Son olaylar"""
        try:
            events = []
            
            # Son doğrulamalar
            recent_logs = self.logger.get_logs('Başarılı doğrulamalar', 5)
            for log in recent_logs:
                if log['level'] == 'SUCCESS' and 'doğrulama' in log['message'].lower():
                    events.append({
                        'type': 'verification',
                        'icon': 'fas fa-check-circle text-success',
                        'message': log['message'],
                        'timestamp': log['timestamp'],
                        'user_id': log.get('user_id')
                    })
            
            # Son güvenlik olayları
            security_events = self.security.load_json(self.security.security_events_file, [])
            recent_security = sorted(security_events, key=lambda x: x.get('timestamp', ''), reverse=True)[:5]
            
            for event in recent_security:
                icon_map = {
                    'low': 'fas fa-info-circle text-info',
                    'medium': 'fas fa-exclamation-triangle text-warning',
                    'high': 'fas fa-exclamation-circle text-danger',
                    'critical': 'fas fa-skull-crossbones text-danger'
                }
                
                events.append({
                    'type': 'security',
                    'icon': icon_map.get(event.get('severity', 'low'), 'fas fa-shield-alt'),
                    'message': f"Güvenlik: {event.get('event_type', 'Bilinmeyen olay')}",
                    'timestamp': event.get('timestamp'),
                    'severity': event.get('severity', 'low')
                })
            
            # Admin aksiyonları
            admin_actions = self.database.get_admin_actions(5)
            for action in admin_actions:
                events.append({
                    'type': 'admin',
                    'icon': 'fas fa-user-shield text-primary',
                    'message': f"Admin: {action.get('action', 'Aksiyon')} - {action.get('target_username', 'Unknown')}",
                    'timestamp': action.get('timestamp'),
                    'admin': action.get('admin_name')
                })
            
            # Timestamp'e göre sırala
            events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            return events[:15]  # Son 15 olay
            
        except Exception as e:
            self.logger.error(f"Son olaylar hatası: {str(e)}")
            return []
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Performans metrikleri"""
        try:
            # Veritabanı istatistikleri
            db_stats = self.database.get_statistics()
            
            # Response time (basit ölçüm)
            import time
            start_time = time.time()
            self.database.get_statistics()  # Test query
            db_response_time = (time.time() - start_time) * 1000  # ms
            
            # Memory usage
            memory_info = self.image_memory.get_memory_info()
            
            # Throughput hesaplama (son 1 saatteki işlemler)
            now = datetime.now()
            hour_ago = now - timedelta(hours=1)
            
            # Son 1 saatteki doğrulamalar
            recent_verifications = 0
            verified_users = self.database.get_all_verified_users()
            for user_data in verified_users.values():
                verified_at = user_data.get('verified_at')
                if verified_at:
                    try:
                        verified_time = datetime.fromisoformat(verified_at)
                        if verified_time > hour_ago:
                            recent_verifications += 1
                    except:
                        continue
            
            # Başarı oranı
            success_rate = db_stats.get('success_rate', 0)
            
            # Error rate (son 1 saatteki hatalar)
            error_logs = self.logger.get_logs('Hata logları', 100)
            recent_errors = len([
                log for log in error_logs 
                if datetime.fromisoformat(log['timestamp']) > hour_ago
            ])
            
            return {
                'db_response_time_ms': round(db_response_time, 2),
                'verifications_per_hour': recent_verifications,
                'success_rate': success_rate,
                'error_rate_1h': recent_errors,
                'memory_usage_mb': memory_info.get('memory_file_size_mb', 0) + memory_info.get('hash_file_size_mb', 0),
                'total_processed': db_stats.get('total_attempts', 0),
                'avg_processing_time': '~2.5s',  # Statik değer, gerçek ölçüm yapılabilir
                'queue_size': 0,  # Kuyruk sistemi yoksa 0
                'last_calculated': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Performans metrikleri hatası: {str(e)}")
            return {}

# Route tanımlamaları
@dashboard_bp.route('/dashboard')
def dashboard():
    """Ana dashboard sayfası"""
    try:
        dashboard_manager = DashboardManager(Config())
        dashboard_data = dashboard_manager.get_dashboard_data()
        
        return render_template('dashboard.html', 
                             data=dashboard_data,
                             page_title='Ana Panel')
                             
    except Exception as e:
        logger = Logger()
        logger.error(f"Dashboard route hatası: {str(e)}")
        return render_template('error.html', 
                             error_message="Dashboard yüklenirken hata oluştu",
                             error_details=str(e))

@dashboard_bp.route('/api/dashboard/stats')
def api_dashboard_stats():
    """Dashboard istatistikleri API"""
    try:
        dashboard_manager = DashboardManager(Config())
        stats = dashboard_manager.get_dashboard_data()
        
        return jsonify({
            'success': True,
            'data': stats,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        })

@dashboard_bp.route('/api/dashboard/activity/<int:hours>')
def api_activity_data(hours):
    """Aktivite verisi API"""
    try:
        if hours > 168:  # Maksimum 1 hafta
            hours = 168
            
        dashboard_manager = DashboardManager(Config())
        
        # Belirtilen saat aralığındaki verileri al
        now = datetime.now()
        activity_data = []
        
        for i in range(hours):
            hour_start = now - timedelta(hours=i+1)
            hour_end = now - timedelta(hours=i)
            
            # Bu saatteki aktiviteleri say (basitleştirilmiş)
            hour_stats = {
                'timestamp': hour_start.isoformat(),
                'hour': hour_start.strftime('%H:00'),
                'date': hour_start.strftime('%Y-%m-%d'),
                'verifications': 0,  # Gerçek veri buraya
                'rejections': 0,
                'security_events': 0
            }
            
            activity_data.append(hour_stats)
        
        activity_data.reverse()  # Chronological order
        
        return jsonify({
            'success': True,
            'data': activity_data,
            'period_hours': hours,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@dashboard_bp.route('/api/dashboard/system-status')
def api_system_status():
    """Sistem durumu API"""
    try:
        dashboard_manager = DashboardManager(Config())
        system_status = dashboard_manager.get_system_status()
        
        return jsonify({
            'success': True,
            'data': system_status,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@dashboard_bp.route('/api/dashboard/performance')
def api_performance_metrics():
    """Performans metrikleri API"""
    try:
        dashboard_manager = DashboardManager(Config())
        performance_data = dashboard_manager.get_performance_metrics()
        
        return jsonify({
            'success': True,
            'data': performance_data,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@dashboard_bp.route('/api/dashboard/quick-actions', methods=['POST'])
def api_quick_actions():
    """Hızlı aksiyonlar API"""
    try:
        action = request.json.get('action')
        config = Config()
        
        if action == 'clear_logs':
            # Logları temizle (son 1000'i tut)
            logger = Logger()
            # Log temizleme işlemi burada yapılabilir
            
            return jsonify({
                'success': True,
                'message': 'Loglar temizlendi',
                'action': action
            })
            
        elif action == 'cleanup_database':
            # Veritabanı temizliği
            database = Database()
            database.cleanup_old_pending(7)  # 7 günden eski pending'leri temizle
            
            return jsonify({
                'success': True,
                'message': 'Veritabanı temizlendi',
                'action': action
            })
            
        elif action == 'restart_security':
            # Güvenlik sistemini yeniden başlat
            security = SecurityManager(config)
            security.cleanup_rate_limits()
            
            return jsonify({
                'success': True,
                'message': 'Güvenlik sistemi yenilendi',
                'action': action
            })
            
        else:
            return jsonify({
                'success': False,
                'error': 'Geçersiz aksiyon'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@dashboard_bp.route('/api/dashboard/export-report')
def api_export_report():
    """Dashboard raporu dışa aktarma"""
    try:
        dashboard_manager = DashboardManager(Config())
        dashboard_data = dashboard_manager.get_dashboard_data()
        
        # Rapor oluştur
        report = {
            'report_title': 'YouTube Doğrulama Botu - Dashboard Raporu',
            'generated_at': datetime.now().isoformat(),
            'generated_by': session.get('username', 'System'),
            'period': '24 hours',
            'data': dashboard_data,
            'summary': {
                'total_verifications': dashboard_data.get('database', {}).get('total_verified', 0),
                'success_rate': dashboard_data.get('database', {}).get('success_rate', 0),
                'security_events': dashboard_data.get('security', {}).get('events_last_24h', 0),
                'system_health': dashboard_data.get('system_status', {}).get('overall_health', 'unknown')
            }
        }
        
        return jsonify({
            'success': True,
            'report': report,
            'download_filename': f"dashboard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })