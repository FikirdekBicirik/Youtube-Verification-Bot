# web/routes/logs.py
from flask import Blueprint, render_template, jsonify, request, session, send_file
from datetime import datetime, timedelta
import json
import io
import zipfile
from typing import Dict, List, Any, Optional

from utils.logger import Logger
from utils.config import Config

logs_bp = Blueprint('logs', __name__)

class LogManager:
    """Log yönetim sınıfı"""
    
    def __init__(self):
        self.logger = Logger()
        
        # Log kategorileri
        self.log_categories = {
            'all': 'Tüm Loglar',
            'verification': 'Doğrulama Logları',
            'security': 'Güvenlik Logları',
            'admin': 'Admin Logları',
            'error': 'Hata Logları',
            'success': 'Başarılı İşlemler',
            'warning': 'Uyarılar',
            'system': 'Sistem Logları'
        }
        
        # Log seviye renkleri
        self.level_colors = {
            'INFO': 'text-info',
            'SUCCESS': 'text-success',
            'WARNING': 'text-warning',
            'ERROR': 'text-danger',
            'DEBUG': 'text-muted',
            'SECURITY': 'text-purple',
            'ADMIN': 'text-primary',
            'VERIFICATION': 'text-success'
        }
        
        # Log filtreleme seçenekleri
        self.time_filters = {
            'last_hour': 'Son 1 Saat',
            'last_24h': 'Son 24 Saat',
            'last_week': 'Son 1 Hafta',
            'last_month': 'Son 1 Ay',
            'custom': 'Özel Tarih Aralığı'
        }
    
    def get_filtered_logs(self, category: str = 'all', time_filter: str = 'last_24h', 
                         limit: int = 100, search_query: str = None,
                         start_date: str = None, end_date: str = None,
                         user_id: int = None) -> Dict[str, Any]:
        """Filtrelenmiş logları getir"""
        try:
            # Temel log verilerini al
            if category == 'all':
                logs = self.logger.get_logs('Son 50 log', limit * 2)  # Daha fazla al, sonra filtrele
            else:
                category_map = {
                    'verification': 'Başarılı doğrulamalar',
                    'security': 'Güvenlik logları',
                    'admin': 'Admin logları',
                    'error': 'Hata logları',
                    'success': 'Başarılı doğrulamalar',
                    'warning': 'Son 50 log',
                    'system': 'Sistem logları'
                }
                logs = self.logger.get_logs(category_map.get(category, 'Son 50 log'), limit * 2)
            
            # Zaman filtresi uygula
            if time_filter != 'custom':
                logs = self.apply_time_filter(logs, time_filter)
            else:
                logs = self.apply_custom_date_filter(logs, start_date, end_date)
            
            # Kategori filtresi
            if category != 'all':
                logs = self.apply_category_filter(logs, category)
            
            # Arama filtresi
            if search_query:
                logs = self.apply_search_filter(logs, search_query)
            
            # Kullanıcı filtresi
            if user_id:
                logs = [log for log in logs if log.get('user_id') == user_id]
            
            # Limit uygula
            logs = logs[:limit]
            
            # Log istatistikleri hesapla
            stats = self.calculate_log_stats(logs)
            
            # Logları zenginleştir
            enriched_logs = self.enrich_logs(logs)
            
            return {
                'logs': enriched_logs,
                'stats': stats,
                'total_count': len(logs),
                'filters_applied': {
                    'category': category,
                    'time_filter': time_filter,
                    'search_query': search_query,
                    'user_id': user_id
                }
            }
            
        except Exception as e:
            self.logger.error(f"Log filtreleme hatası: {str(e)}")
            return {'logs': [], 'stats': {}, 'total_count': 0}
    
    def apply_time_filter(self, logs: List[Dict], time_filter: str) -> List[Dict]:
        """Zaman filtresi uygula"""
        now = datetime.now()
        
        if time_filter == 'last_hour':
            cutoff = now - timedelta(hours=1)
        elif time_filter == 'last_24h':
            cutoff = now - timedelta(hours=24)
        elif time_filter == 'last_week':
            cutoff = now - timedelta(weeks=1)
        elif time_filter == 'last_month':
            cutoff = now - timedelta(days=30)
        else:
            return logs
        
        filtered_logs = []
        for log in logs:
            try:
                log_time = datetime.fromisoformat(log['timestamp'])
                if log_time >= cutoff:
                    filtered_logs.append(log)
            except:
                continue
        
        return filtered_logs
    
    def apply_custom_date_filter(self, logs: List[Dict], start_date: str, end_date: str) -> List[Dict]:
        """Özel tarih aralığı filtresi"""
        if not start_date or not end_date:
            return logs
        
        try:
            start_dt = datetime.fromisoformat(start_date)
            end_dt = datetime.fromisoformat(end_date)
            
            filtered_logs = []
            for log in logs:
                try:
                    log_time = datetime.fromisoformat(log['timestamp'])
                    if start_dt <= log_time <= end_dt:
                        filtered_logs.append(log)
                except:
                    continue
            
            return filtered_logs
            
        except Exception as e:
            self.logger.error(f"Özel tarih filtresi hatası: {str(e)}")
            return logs
    
    def apply_category_filter(self, logs: List[Dict], category: str) -> List[Dict]:
        """Kategori filtresi uygula"""
        category_keywords = {
            'verification': ['doğrulama', 'verification', 'verified', 'onaylandı'],
            'security': ['security', 'güvenlik', 'suspicious', 'şüpheli', 'blocked'],
            'admin': ['admin', 'yönetici', 'manuel', 'manual'],
            'error': ['error', 'hata', 'exception', 'failed'],
            'success': ['success', 'başarılı', 'completed', 'approved'],
            'warning': ['warning', 'uyarı', 'caution'],
            'system': ['system', 'sistem', 'startup', 'shutdown']
        }
        
        keywords = category_keywords.get(category, [])
        if not keywords:
            return logs
        
        filtered_logs = []
        for log in logs:
            message_lower = log.get('message', '').lower()
            level_lower = log.get('level', '').lower()
            
            # Level kontrolü
            if category == 'error' and level_lower == 'error':
                filtered_logs.append(log)
                continue
            elif category == 'success' and level_lower == 'success':
                filtered_logs.append(log)
                continue
            elif category == 'warning' and level_lower == 'warning':
                filtered_logs.append(log)
                continue
            
            # Keyword kontrolü
            for keyword in keywords:
                if keyword in message_lower:
                    filtered_logs.append(log)
                    break
        
        return filtered_logs
    
    def apply_search_filter(self, logs: List[Dict], search_query: str) -> List[Dict]:
        """Arama filtresi uygula"""
        search_lower = search_query.lower()
        
        filtered_logs = []
        for log in logs:
            # Mesaj içeriğinde ara
            if search_lower in log.get('message', '').lower():
                filtered_logs.append(log)
                continue
            
            # Kullanıcı ID'sinde ara
            if search_query.isdigit() and str(log.get('user_id', '')) == search_query:
                filtered_logs.append(log)
                continue
            
            # Extra data içinde ara
            extra_data = log.get('extra_data', {})
            if isinstance(extra_data, dict):
                for key, value in extra_data.items():
                    if search_lower in str(value).lower():
                        filtered_logs.append(log)
                        break
        
        return filtered_logs
    
    def calculate_log_stats(self, logs: List[Dict]) -> Dict[str, Any]:
        """Log istatistikleri hesapla"""
        if not logs:
            return {}
        
        # Level dağılımı
        level_counts = {}
        for log in logs:
            level = log.get('level', 'UNKNOWN')
            level_counts[level] = level_counts.get(level, 0) + 1
        
        # Saatlik dağılım (son 24 saat)
        hourly_distribution = {}
        for log in logs:
            try:
                log_time = datetime.fromisoformat(log['timestamp'])
                hour_key = log_time.strftime('%H:00')
                hourly_distribution[hour_key] = hourly_distribution.get(hour_key, 0) + 1
            except:
                continue
        
        # En aktif kullanıcılar
        user_activity = {}
        for log in logs:
            user_id = log.get('user_id')
            if user_id:
                user_activity[user_id] = user_activity.get(user_id, 0) + 1
        
        top_users = sorted(user_activity.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Zaman aralığı
        timestamps = [log['timestamp'] for log in logs if 'timestamp' in log]
        if timestamps:
            timestamps.sort()
            time_range = {
                'start': timestamps[0],
                'end': timestamps[-1]
            }
        else:
            time_range = {}
        
        return {
            'total_logs': len(logs),
            'level_distribution': level_counts,
            'hourly_distribution': hourly_distribution,
            'top_users': top_users,
            'time_range': time_range,
            'unique_users': len(user_activity),
            'error_rate': (level_counts.get('ERROR', 0) / len(logs)) * 100 if logs else 0
        }
    
    def enrich_logs(self, logs: List[Dict]) -> List[Dict]:
        """Logları zenginleştir (ek bilgiler ekle)"""
        enriched = []
        
        for log in logs:
            enriched_log = log.copy()
            
            # Renk sınıfı ekle
            level = log.get('level', 'INFO')
            enriched_log['color_class'] = self.level_colors.get(level, 'text-muted')
            
            # Icon ekle
            enriched_log['icon'] = self.get_log_icon(level, log.get('message', ''))
            
            # Relative time ekle
            try:
                log_time = datetime.fromisoformat(log['timestamp'])
                now = datetime.now()
                diff = now - log_time
                
                if diff.days > 0:
                    enriched_log['relative_time'] = f"{diff.days} gün önce"
                elif diff.seconds > 3600:
                    hours = diff.seconds // 3600
                    enriched_log['relative_time'] = f"{hours} saat önce"
                elif diff.seconds > 60:
                    minutes = diff.seconds // 60
                    enriched_log['relative_time'] = f"{minutes} dakika önce"
                else:
                    enriched_log['relative_time'] = "Az önce"
            except:
                enriched_log['relative_time'] = "Bilinmiyor"
            
            # Severity score ekle
            enriched_log['severity_score'] = self.get_severity_score(level)
            
            # Mesajı parse et
            enriched_log['parsed_message'] = self.parse_log_message(log.get('message', ''))
            
            enriched.append(enriched_log)
        
        return enriched
    
    def get_log_icon(self, level: str, message: str) -> str:
        """Log için uygun icon"""
        if level == 'ERROR':
            return 'fas fa-exclamation-circle'
        elif level == 'SUCCESS':
            return 'fas fa-check-circle'
        elif level == 'WARNING':
            return 'fas fa-exclamation-triangle'
        elif level == 'SECURITY':
            return 'fas fa-shield-alt'
        elif level == 'ADMIN':
            return 'fas fa-user-shield'
        elif level == 'VERIFICATION':
            return 'fas fa-certificate'
        elif 'doğrulama' in message.lower():
            return 'fas fa-user-check'
        elif 'bot' in message.lower():
            return 'fas fa-robot'
        else:
            return 'fas fa-info-circle'
    
    def get_severity_score(self, level: str) -> int:
        """Severity score (1-10)"""
        severity_map = {
            'DEBUG': 1,
            'INFO': 3,
            'SUCCESS': 4,
            'WARNING': 6,
            'ERROR': 8,
            'SECURITY': 9,
            'CRITICAL': 10
        }
        return severity_map.get(level, 5)
    
    def parse_log_message(self, message: str) -> Dict[str, str]:
        """Log mesajını parse et"""
        # Basit parsing
        parsed = {
            'main_message': message,
            'action': None,
            'target': None,
            'details': None
        }
        
        # Admin aksiyonları
        if 'Admin aksiyonu:' in message:
            parts = message.split(' - ')
            if len(parts) >= 2:
                parsed['action'] = parts[0].replace('Admin aksiyonu:', '').strip()
                parsed['target'] = parts[1] if len(parts) > 1 else None
        
        # Doğrulama mesajları
        elif 'Doğrulama denemesi:' in message:
            parts = message.split(' - ')
            if len(parts) >= 2:
                parsed['action'] = 'Doğrulama'
                parsed['target'] = parts[0].replace('Doğrulama denemesi:', '').strip()
                parsed['details'] = parts[1] if len(parts) > 1 else None
        
        return parsed
    
    def export_logs(self, logs: List[Dict], format_type: str = 'json') -> bytes:
        """Logları dışa aktar"""
        if format_type == 'json':
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'total_logs': len(logs),
                'logs': logs
            }
            return json.dumps(export_data, indent=2, ensure_ascii=False).encode('utf-8')
        
        elif format_type == 'csv':
            import csv
            output = io.StringIO()
            
            if logs:
                fieldnames = ['timestamp', 'level', 'message', 'user_id', 'extra_data']
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                
                for log in logs:
                    writer.writerow({
                        'timestamp': log.get('timestamp', ''),
                        'level': log.get('level', ''),
                        'message': log.get('message', ''),
                        'user_id': log.get('user_id', ''),
                        'extra_data': json.dumps(log.get('extra_data', {}))
                    })
            
            return output.getvalue().encode('utf-8')
        
        elif format_type == 'txt':
            lines = []
            for log in logs:
                line = f"[{log.get('timestamp', '')}] {log.get('level', 'INFO')}: {log.get('message', '')}"
                if log.get('user_id'):
                    line += f" (User: {log['user_id']})"
                lines.append(line)
            
            return '\n'.join(lines).encode('utf-8')
        
        else:
            raise ValueError(f"Desteklenmeyen format: {format_type}")

# Route tanımlamaları
@logs_bp.route('/logs')
def logs():
    """Log görüntüleme sayfası"""
    try:
        log_manager = LogManager()
        
        # URL parametrelerini al
        category = request.args.get('category', 'all')
        time_filter = request.args.get('time_filter', 'last_24h')
        limit = int(request.args.get('limit', 100))
        search_query = request.args.get('search', '')
        user_id = request.args.get('user_id', type=int)
        
        # Logları getir
        log_data = log_manager.get_filtered_logs(
            category=category,
            time_filter=time_filter,
            limit=limit,
            search_query=search_query,
            user_id=user_id
        )
        
        return render_template('logs.html',
            log_data=log_data,
            log_categories=log_manager.log_categories,
            time_filters=log_manager.time_filters,
            current_filters={
                'category': category,
                'time_filter': time_filter,
                'limit': limit,
                'search_query': search_query,
                'user_id': user_id
            }
        )
        
    except Exception as e:
        logger = Logger()
        logger.error(f"Log sayfası hatası: {str(e)}")
        return render_template('error.html', 
                             error_message="Log sayfası yüklenirken hata oluştu")

@logs_bp.route('/api/logs')
def api_logs():
    """Log API endpoint"""
    try:
        log_manager = LogManager()
        
        # Parametreleri al
        category = request.args.get('category', 'all')
        time_filter = request.args.get('time_filter', 'last_24h')
        limit = int(request.args.get('limit', 50))
        search_query = request.args.get('search')
        user_id = request.args.get('user_id', type=int)
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Logları getir
        log_data = log_manager.get_filtered_logs(
            category=category,
            time_filter=time_filter,
            limit=limit,
            search_query=search_query,
            start_date=start_date,
            end_date=end_date,
            user_id=user_id
        )
        
        return jsonify({
            'success': True,
            'data': log_data,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@logs_bp.route('/api/logs/export')
def api_export_logs():
    """Log dışa aktarma API"""
    try:
        log_manager = LogManager()
        
        # Parametreleri al
        format_type = request.args.get('format', 'json')
        category = request.args.get('category', 'all')
        time_filter = request.args.get('time_filter', 'last_24h')
        limit = int(request.args.get('limit', 1000))
        
        # Logları getir
        log_data = log_manager.get_filtered_logs(
            category=category,
            time_filter=time_filter,
            limit=limit
        )
        
        # Export et
        export_data = log_manager.export_logs(log_data['logs'], format_type)
        
        # Dosya adı oluştur
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"logs_export_{timestamp}.{format_type}"
        
        # Content type belirle
        content_type_map = {
            'json': 'application/json',
            'csv': 'text/csv',
            'txt': 'text/plain'
        }
        
        return send_file(
            io.BytesIO(export_data),
            mimetype=content_type_map.get(format_type, 'application/octet-stream'),
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@logs_bp.route('/api/logs/stats')
def api_log_stats():
    """Log istatistikleri API"""
    try:
        log_manager = LogManager()
        
        # Son 24 saatin loglarını al
        log_data = log_manager.get_filtered_logs(
            category='all',
            time_filter='last_24h',
            limit=10000
        )
        
        return jsonify({
            'success': True,
            'data': log_data['stats'],
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@logs_bp.route('/api/logs/clear', methods=['POST'])
def api_clear_logs():
    """Log temizleme API (admin only)"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Admin yetkisi gerekli'
            }), 403
        
        # Log temizleme işlemi
        logger = Logger()
        logger.cleanup_old_logs(days=7)  # 7 günden eski logları temizle
        
        # Admin log
        admin_username = session.get('username', 'Unknown')
        logger.admin_action(0, admin_username, 'log_cleanup', 'system')
        
        return jsonify({
            'success': True,
            'message': 'Loglar temizlendi'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })