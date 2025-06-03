# web/routes/settings.py
from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for, flash
from datetime import datetime
import json
import os
import shutil
from typing import Dict, List, Any, Optional

from utils.logger import Logger
from utils.config import Config
from bot.database import Database
from bot.security import SecurityManager

settings_bp = Blueprint('settings', __name__)

class SettingsManager:
    """Ayarlar yönetim sınıfı"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger()
        self.database = Database()
        self.security = SecurityManager(config)
        
        # Ayar kategorileri
        self.setting_categories = {
            'verification': {
                'title': 'Doğrulama Ayarları',
                'icon': 'fas fa-check-circle',
                'description': 'YouTube doğrulama kriterleri ve kuralları'
            },
            'security': {
                'title': 'Güvenlik Ayarları',
                'icon': 'fas fa-shield-alt',
                'description': 'Rate limiting, blacklist ve güvenlik kontrolleri'
            },
            'automation': {
                'title': 'Otomasyon Ayarları',
                'icon': 'fas fa-robot',
                'description': 'Otomatik doğrulama ve manuel inceleme eşikleri'
            },
            'notifications': {
                'title': 'Bildirim Ayarları',
                'icon': 'fas fa-bell',
                'description': 'Log bildirimleri ve admin uyarıları'
            },
            'advanced': {
                'title': 'Gelişmiş Ayarlar',
                'icon': 'fas fa-cogs',
                'description': 'OCR, resim hafızası ve diğer gelişmiş özellikler'
            },
            'system': {
                'title': 'Sistem Ayarları',
                'icon': 'fas fa-server',
                'description': 'Veritabanı, yedekleme ve sistem yapılandırması'
            }
        }
        
        # Ayar tanımları
        self.setting_definitions = self.define_settings()
    
    def define_settings(self) -> Dict[str, Dict]:
        """Tüm ayar tanımlarını oluştur"""
        return {
            # Doğrulama Ayarları
            'SUBSCRIBE_REQUIRED': {
                'category': 'verification',
                'type': 'boolean',
                'title': 'Abone Olma Zorunlu',
                'description': 'Kullanıcıların kanala abone olması zorunlu mu?',
                'default': True,
                'requires_restart': False
            },
            'LIKE_REQUIRED': {
                'category': 'verification',
                'type': 'boolean',
                'title': 'Beğeni Zorunlu',
                'description': 'Kullanıcıların videoyu beğenmesi zorunlu mu?',
                'default': True,
                'requires_restart': False
            },
            'COMMENT_REQUIRED': {
                'category': 'verification',
                'type': 'boolean',
                'title': 'Yorum Zorunlu',
                'description': 'Kullanıcıların yorum yapması zorunlu mu?',
                'default': True,
                'requires_restart': False
            },
            'MIN_CONFIDENCE': {
                'category': 'verification',
                'type': 'range',
                'title': 'Minimum Güven Skoru',
                'description': 'Doğrulama için gereken minimum güven skoru (0-100)',
                'default': 75,
                'min': 0,
                'max': 100,
                'requires_restart': False
            },
            'YOUR_CHANNEL_NAME': {
                'category': 'verification',
                'type': 'text',
                'title': 'YouTube Kanal Adı',
                'description': 'Doğrulanacak YouTube kanal adı',
                'default': 'KanalAdınız',
                'required': True,
                'requires_restart': True
            },
            'YOUR_CHANNEL_ID': {
                'category': 'verification',
                'type': 'text',
                'title': 'YouTube Kanal ID',
                'description': 'YouTube kanal ID\'si (opsiyonel)',
                'default': '',
                'required': False,
                'requires_restart': True
            },
            
            # Güvenlik Ayarları
            'RATE_LIMIT_REQUESTS': {
                'category': 'security',
                'type': 'number',
                'title': 'Rate Limit - İstek Sayısı',
                'description': 'Zaman penceresinde izin verilen maksimum istek sayısı',
                'default': 3,
                'min': 1,
                'max': 20,
                'requires_restart': False
            },
            'RATE_LIMIT_WINDOW': {
                'category': 'security',
                'type': 'number',
                'title': 'Rate Limit - Zaman Penceresi (saniye)',
                'description': 'Rate limit için zaman penceresi',
                'default': 300,
                'min': 60,
                'max': 3600,
                'requires_restart': False
            },
            'MAX_FILE_SIZE': {
                'category': 'security',
                'type': 'number',
                'title': 'Maksimum Dosya Boyutu (MB)',
                'description': 'Yüklenebilecek maksimum dosya boyutu',
                'default': 15,
                'min': 1,
                'max': 50,
                'requires_restart': False
            },
            'DUPLICATE_CHECK': {
                'category': 'security',
                'type': 'boolean',
                'title': 'Duplicate Resim Kontrolü',
                'description': 'Aynı resmin tekrar kullanılmasını engelle',
                'default': True,
                'requires_restart': False
            },
            'SECURITY_LOGS': {
                'category': 'security',
                'type': 'boolean',
                'title': 'Güvenlik Logları',
                'description': 'Detaylı güvenlik loglarını etkinleştir',
                'default': True,
                'requires_restart': False
            },
            
            # Otomasyon Ayarları
            'AUTO_VERIFICATION': {
                'category': 'automation',
                'type': 'boolean',
                'title': 'Otomatik Doğrulama',
                'description': 'Yüksek güven skorlu istekleri otomatik onayla',
                'default': True,
                'requires_restart': False
            },
            'AUTO_APPROVE_THRESHOLD': {
                'category': 'automation',
                'type': 'range',
                'title': 'Otomatik Onay Eşiği',
                'description': 'Bu skorun üzerindeki istekler otomatik onaylanır',
                'default': 80,
                'min': 50,
                'max': 100,
                'requires_restart': False
            },
            'MANUAL_REVIEW_THRESHOLD': {
                'category': 'automation',
                'type': 'range',
                'title': 'Manuel İnceleme Eşiği',
                'description': 'Bu skorun altındaki istekler manuel incelemeye gider',
                'default': 40,
                'min': 0,
                'max': 80,
                'requires_restart': False
            },
            'DELETE_FAILED_ATTEMPTS': {
                'category': 'automation',
                'type': 'boolean',
                'title': 'Başarısız Denemeleri Sil',
                'description': 'Başarısız doğrulama mesajlarını otomatik sil',
                'default': True,
                'requires_restart': False
            },
            
            # Bildirim Ayarları
            'DM_NOTIFICATIONS': {
                'category': 'notifications',
                'type': 'boolean',
                'title': 'DM Bildirimleri',
                'description': 'Kullanıcılara özel mesaj gönder',
                'default': True,
                'requires_restart': False
            },
            'ADMIN_NOTIFICATIONS': {
                'category': 'notifications',
                'type': 'boolean',
                'title': 'Admin Bildirimleri',
                'description': 'Yöneticilere kritik olaylar için bildirim gönder',
                'default': True,
                'requires_restart': False
            },
            'LOG_LEVEL': {
                'category': 'notifications',
                'type': 'select',
                'title': 'Log Seviyesi',
                'description': 'Minimum log seviyesi',
                'default': 'INFO',
                'options': ['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                'requires_restart': True
            },
            
            # Gelişmiş Ayarlar
            'ENABLE_IMAGE_MEMORY': {
                'category': 'advanced',
                'type': 'boolean',
                'title': 'Resim Hafızası',
                'description': 'Resim hafızası sistemini etkinleştir',
                'default': True,
                'requires_restart': False
            },
            'OCR_LANGUAGE': {
                'category': 'advanced',
                'type': 'select',
                'title': 'OCR Dili',
                'description': 'Metin tanıma için kullanılacak dil',
                'default': 'tur+eng',
                'options': ['tur', 'eng', 'tur+eng'],
                'requires_restart': True
            },
            'OCR_CONFIDENCE_THRESHOLD': {
                'category': 'advanced',
                'type': 'range',
                'title': 'OCR Güven Eşiği',
                'description': 'OCR için minimum güven skoru',
                'default': 60,
                'min': 30,
                'max': 95,
                'requires_restart': False
            },
            'OCR_DEBUG': {
                'category': 'advanced',
                'type': 'boolean',
                'title': 'OCR Debug Modu',
                'description': 'OCR debug bilgilerini kaydet',
                'default': False,
                'requires_restart': False
            },
            
            # Sistem Ayarları
            'WEB_PORT': {
                'category': 'system',
                'type': 'number',
                'title': 'Web Panel Portu',
                'description': 'Web paneli için port numarası',
                'default': 5000,
                'min': 1000,
                'max': 65535,
                'requires_restart': True
            },
            'WEB_DEBUG': {
                'category': 'system',
                'type': 'boolean',
                'title': 'Web Debug Modu',
                'description': 'Web paneli debug modunu etkinleştir',
                'default': False,
                'requires_restart': True
            },
            'AUTO_BACKUP': {
                'category': 'system',
                'type': 'boolean',
                'title': 'Otomatik Yedekleme',
                'description': 'Veritabanının otomatik yedeklenmesi',
                'default': True,
                'requires_restart': False
            },
            'BACKUP_INTERVAL_HOURS': {
                'category': 'system',
                'type': 'number',
                'title': 'Yedekleme Aralığı (Saat)',
                'description': 'Otomatik yedekleme aralığı',
                'default': 24,
                'min': 1,
                'max': 168,
                'requires_restart': False
            }
        }
    
    def get_current_settings(self) -> Dict[str, Any]:
        """Mevcut ayarları getir"""
        try:
            current_settings = {}
            
            for setting_key, setting_def in self.setting_definitions.items():
                current_value = self.config.get(setting_key, setting_def['default'])
                
                # Tip kontrolü ve dönüşümü
                if setting_def['type'] == 'boolean':
                    current_value = bool(current_value)
                elif setting_def['type'] in ['number', 'range']:
                    current_value = int(current_value) if isinstance(current_value, (int, float, str)) else setting_def['default']
                elif setting_def['type'] in ['text', 'select']:
                    current_value = str(current_value)
                
                current_settings[setting_key] = {
                    'value': current_value,
                    'definition': setting_def
                }
            
            return current_settings
            
        except Exception as e:
            self.logger.error(f"Ayarları alma hatası: {str(e)}")
            return {}
    
    def get_settings_by_category(self) -> Dict[str, Dict]:
        """Kategoriye göre gruplandırılmış ayarlar"""
        try:
            current_settings = self.get_current_settings()
            categorized = {}
            
            for category_key, category_info in self.setting_categories.items():
                categorized[category_key] = {
                    'info': category_info,
                    'settings': {}
                }
                
                for setting_key, setting_data in current_settings.items():
                    if setting_data['definition']['category'] == category_key:
                        categorized[category_key]['settings'][setting_key] = setting_data
            
            return categorized
            
        except Exception as e:
            self.logger.error(f"Kategorili ayarlar hatası: {str(e)}")
            return {}
    
    def update_settings(self, updates: Dict[str, Any], admin_user: str) -> Dict[str, Any]:
        """Ayarları güncelle"""
        try:
            updated_settings = []
            validation_errors = []
            requires_restart = False
            
            for setting_key, new_value in updates.items():
                if setting_key not in self.setting_definitions:
                    validation_errors.append(f"Bilinmeyen ayar: {setting_key}")
                    continue
                
                setting_def = self.setting_definitions[setting_key]
                
                # Değer doğrulaması
                validation_result = self.validate_setting_value(setting_key, new_value, setting_def)
                
                if not validation_result['valid']:
                    validation_errors.append(f"{setting_key}: {validation_result['error']}")
                    continue
                
                # Mevcut değeri al
                current_value = self.config.get(setting_key, setting_def['default'])
                validated_value = validation_result['value']
                
                # Değer değişti mi?
                if current_value != validated_value:
                    # Güncelle
                    self.config.set(setting_key, validated_value)
                    
                    updated_settings.append({
                        'key': setting_key,
                        'old_value': current_value,
                        'new_value': validated_value,
                        'title': setting_def['title']
                    })
                    
                    # Restart gerekli mi?
                    if setting_def.get('requires_restart', False):
                        requires_restart = True
            
            # Admin aksiyonu kaydet
            if updated_settings:
                self.logger.admin_action(
                    0, admin_user, 'settings_update', 'system',
                    {
                        'updated_count': len(updated_settings),
                        'updates': updated_settings,
                        'requires_restart': requires_restart
                    }
                )
            
            return {
                'success': True,
                'updated_settings': updated_settings,
                'validation_errors': validation_errors,
                'requires_restart': requires_restart,
                'updated_count': len(updated_settings)
            }
            
        except Exception as e:
            self.logger.error(f"Ayar güncelleme hatası: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'updated_settings': [],
                'validation_errors': []
            }
    
    def validate_setting_value(self, setting_key: str, value: Any, setting_def: Dict) -> Dict[str, Any]:
        """Ayar değerini doğrula"""
        try:
            setting_type = setting_def['type']
            
            if setting_type == 'boolean':
                if isinstance(value, bool):
                    return {'valid': True, 'value': value}
                elif isinstance(value, str):
                    return {'valid': True, 'value': value.lower() in ['true', '1', 'yes', 'on']}
                elif isinstance(value, (int, float)):
                    return {'valid': True, 'value': bool(value)}
                else:
                    return {'valid': False, 'error': 'Boolean değer bekleniyor'}
            
            elif setting_type in ['number', 'range']:
                try:
                    num_value = int(value) if isinstance(value, str) else value
                    
                    # Min/max kontrolü
                    if 'min' in setting_def and num_value < setting_def['min']:
                        return {'valid': False, 'error': f"Minimum değer: {setting_def['min']}"}
                    if 'max' in setting_def and num_value > setting_def['max']:
                        return {'valid': False, 'error': f"Maksimum değer: {setting_def['max']}"}
                    
                    return {'valid': True, 'value': num_value}
                except (ValueError, TypeError):
                    return {'valid': False, 'error': 'Sayısal değer bekleniyor'}
            
            elif setting_type == 'text':
                str_value = str(value).strip()
                
                # Gerekli alan kontrolü
                if setting_def.get('required', False) and not str_value:
                    return {'valid': False, 'error': 'Bu alan gereklidir'}
                
                # Özel validasyonlar
                if setting_key == 'YOUR_CHANNEL_NAME' and len(str_value) < 3:
                    return {'valid': False, 'error': 'Kanal adı en az 3 karakter olmalı'}
                
                return {'valid': True, 'value': str_value}
            
            elif setting_type == 'select':
                str_value = str(value)
                options = setting_def.get('options', [])
                
                if str_value not in options:
                    return {'valid': False, 'error': f"Geçerli seçenekler: {', '.join(options)}"}
                
                return {'valid': True, 'value': str_value}
            
            else:
                return {'valid': False, 'error': f"Bilinmeyen ayar tipi: {setting_type}"}
                
        except Exception as e:
            return {'valid': False, 'error': f"Doğrulama hatası: {str(e)}"}
    
    def reset_settings(self, category: str = None, admin_user: str = None) -> Dict[str, Any]:
        """Ayarları varsayılana sıfırla"""
        try:
            reset_settings = []
            
            for setting_key, setting_def in self.setting_definitions.items():
                # Kategori filtresi
                if category and setting_def['category'] != category:
                    continue
                
                current_value = self.config.get(setting_key)
                default_value = setting_def['default']
                
                if current_value != default_value:
                    self.config.set(setting_key, default_value)
                    reset_settings.append({
                        'key': setting_key,
                        'title': setting_def['title'],
                        'old_value': current_value,
                        'new_value': default_value
                    })
            
            # Admin aksiyonu kaydet
            if reset_settings and admin_user:
                self.logger.admin_action(
                    0, admin_user, 'settings_reset', 'system',
                    {
                        'category': category or 'all',
                        'reset_count': len(reset_settings),
                        'reset_settings': reset_settings
                    }
                )
            
            return {
                'success': True,
                'reset_count': len(reset_settings),
                'reset_settings': reset_settings
            }
            
        except Exception as e:
            self.logger.error(f"Ayar sıfırlama hatası: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'reset_count': 0
            }
    
    def export_settings(self) -> Dict[str, Any]:
        """Ayarları dışa aktar"""
        try:
            current_settings = self.get_current_settings()
            
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'bot_version': '3.0.0',
                'settings': {}
            }
            
            for setting_key, setting_data in current_settings.items():
                export_data['settings'][setting_key] = {
                    'value': setting_data['value'],
                    'category': setting_data['definition']['category'],
                    'title': setting_data['definition']['title']
                }
            
            return {
                'success': True,
                'data': export_data
            }
            
        except Exception as e:
            self.logger.error(f"Ayar dışa aktarma hatası: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def import_settings(self, import_data: Dict[str, Any], admin_user: str) -> Dict[str, Any]:
        """Ayarları içe aktar"""
        try:
            if 'settings' not in import_data:
                return {'success': False, 'error': 'Geçersiz import dosyası'}
            
            imported_settings = []
            errors = []
            
            for setting_key, setting_data in import_data['settings'].items():
                if setting_key not in self.setting_definitions:
                    errors.append(f"Bilinmeyen ayar: {setting_key}")
                    continue
                
                new_value = setting_data.get('value')
                setting_def = self.setting_definitions[setting_key]
                
                # Doğrula
                validation_result = self.validate_setting_value(setting_key, new_value, setting_def)
                
                if validation_result['valid']:
                    current_value = self.config.get(setting_key)
                    if current_value != validation_result['value']:
                        self.config.set(setting_key, validation_result['value'])
                        imported_settings.append({
                            'key': setting_key,
                            'title': setting_def['title'],
                            'old_value': current_value,
                            'new_value': validation_result['value']
                        })
                else:
                    errors.append(f"{setting_key}: {validation_result['error']}")
            
            # Admin aksiyonu kaydet
            if imported_settings:
                self.logger.admin_action(
                    0, admin_user, 'settings_import', 'system',
                    {
                        'imported_count': len(imported_settings),
                        'error_count': len(errors),
                        'source': import_data.get('exported_at', 'unknown')
                    }
                )
            
            return {
                'success': True,
                'imported_count': len(imported_settings),
                'imported_settings': imported_settings,
                'errors': errors
            }
            
        except Exception as e:
            self.logger.error(f"Ayar içe aktarma hatası: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_system_info(self) -> Dict[str, Any]:
        """Sistem bilgilerini getir"""
        try:
            import psutil
            import platform
            
            # Sistem bilgileri
            system_info = {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'cpu_count': psutil.cpu_count(),
                'memory_total_gb': round(psutil.virtual_memory().total / (1024**3), 2),
                'disk_total_gb': round(shutil.disk_usage('.').total / (1024**3), 2),
                'disk_free_gb': round(shutil.disk_usage('.').free / (1024**3), 2)
            }
            
            # Bot bilgileri
            bot_info = {
                'version': '3.0.0',
                'config_file': self.config.config_file,
                'data_directory': 'data/',
                'log_directory': 'data/logs/',
                'backup_directory': 'data/backups/'
            }
            
            # Veritabanı bilgileri
            db_info = self.database.get_database_info()
            
            # Güvenlik durumu
            security_stats = self.security.get_security_statistics()
            
            return {
                'system': system_info,
                'bot': bot_info,
                'database': db_info,
                'security': {
                    'total_events': security_stats.get('total_security_events', 0),
                    'suspicious_users': security_stats.get('suspicious_users', {}).get('total', 0),
                    'blacklist_size': sum(security_stats.get('blacklist_sizes', {}).values())
                }
            }
            
        except Exception as e:
            self.logger.error(f"Sistem bilgisi hatası: {str(e)}")
            return {}

# Route tanımlamaları
@settings_bp.route('/settings')
def settings():
    """Ayarlar ana sayfası"""
    try:
        if session.get('user_role') != 'admin':
            flash('Bu sayfa sadece adminler tarafından erişilebilir!', 'error')
            return redirect(url_for('dashboard'))
        
        config = Config()
        settings_manager = SettingsManager(config)
        
        # Kategoriye göre gruplandırılmış ayarları getir
        categorized_settings = settings_manager.get_settings_by_category()
        
        # Sistem bilgilerini getir
        system_info = settings_manager.get_system_info()
        
        return render_template('settings.html',
            categorized_settings=categorized_settings,
            system_info=system_info,
            active_category=request.args.get('category', 'verification')
        )
        
    except Exception as e:
        logger = Logger()
        logger.error(f"Ayarlar sayfası hatası: {str(e)}")
        flash('Ayarlar sayfası yüklenirken hata oluştu!', 'error')
        return redirect(url_for('dashboard'))

@settings_bp.route('/api/settings')
def api_get_settings():
    """Ayarları getir API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        settings_manager = SettingsManager(config)
        
        category = request.args.get('category')
        
        if category:
            categorized_settings = settings_manager.get_settings_by_category()
            category_data = categorized_settings.get(category, {})
            
            return jsonify({
                'success': True,
                'data': category_data,
                'timestamp': datetime.now().isoformat()
            })
        else:
            current_settings = settings_manager.get_current_settings()
            
            return jsonify({
                'success': True,
                'data': current_settings,
                'timestamp': datetime.now().isoformat()
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@settings_bp.route('/api/settings/update', methods=['POST'])
def api_update_settings():
    """Ayarları güncelle API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        settings_manager = SettingsManager(config)
        
        updates = request.get_json()
        if not updates:
            return jsonify({'success': False, 'error': 'Güncelleme verisi bulunamadı'})
        
        admin_user = session.get('username', 'Unknown')
        
        # Ayarları güncelle
        result = settings_manager.update_settings(updates, admin_user)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': f"{result['updated_count']} ayar güncellendi",
                'data': result,
                'requires_restart': result['requires_restart']
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Güncelleme başarısız'),
                'validation_errors': result.get('validation_errors', [])
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@settings_bp.route('/api/settings/reset', methods=['POST'])
def api_reset_settings():
    """Ayarları sıfırla API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        settings_manager = SettingsManager(config)
        
        category = request.get_json().get('category') if request.is_json else None
        admin_user = session.get('username', 'Unknown')
        
        # Ayarları sıfırla
        result = settings_manager.reset_settings(category, admin_user)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': f"{result['reset_count']} ayar varsayılana sıfırlandı",
                'data': result
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Sıfırlama başarısız')
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@settings_bp.route('/api/settings/export')
def api_export_settings():
    """Ayarları dışa aktar API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        settings_manager = SettingsManager(config)
        
        result = settings_manager.export_settings()
        
        if result['success']:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"bot_settings_{timestamp}.json"
            
            return jsonify({
                'success': True,
                'data': result['data'],
                'download_filename': filename
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Dışa aktarma başarısız')
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@settings_bp.route('/api/settings/import', methods=['POST'])
def api_import_settings():
    """Ayarları içe aktar API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        settings_manager = SettingsManager(config)
        
        import_data = request.get_json()
        if not import_data:
            return jsonify({'success': False, 'error': 'İçe aktarma verisi bulunamadı'})
        
        admin_user = session.get('username', 'Unknown')
        
        # Ayarları içe aktar
        result = settings_manager.import_settings(import_data, admin_user)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': f"{result['imported_count']} ayar içe aktarıldı",
                'data': result
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'İçe aktarma başarısız'),
                'errors': result.get('errors', [])
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@settings_bp.route('/api/settings/validate', methods=['POST'])
def api_validate_settings():
    """Ayar değerlerini doğrula API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        settings_manager = SettingsManager(config)
        
        validation_data = request.get_json()
        if not validation_data:
            return jsonify({'success': False, 'error': 'Doğrulama verisi bulunamadı'})
        
        validation_results = {}
        
        for setting_key, value in validation_data.items():
            if setting_key in settings_manager.setting_definitions:
                setting_def = settings_manager.setting_definitions[setting_key]
                result = settings_manager.validate_setting_value(setting_key, value, setting_def)
                validation_results[setting_key] = result
            else:
                validation_results[setting_key] = {
                    'valid': False,
                    'error': 'Bilinmeyen ayar'
                }
        
        return jsonify({
            'success': True,
            'validation_results': validation_results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@settings_bp.route('/api/settings/system-info')
def api_system_info():
    """Sistem bilgilerini getir API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        settings_manager = SettingsManager(config)
        
        system_info = settings_manager.get_system_info()
        
        return jsonify({
            'success': True,
            'data': system_info,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@settings_bp.route('/api/settings/backup', methods=['POST'])
def api_create_backup():
    """Sistem yedeği oluştur API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        database = Database()
        logger = Logger()
        
        # Yedek oluştur
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = f"data/backups/backup_{timestamp}"
        
        success = database.backup_database(backup_path)
        
        if success:
            admin_user = session.get('username', 'Unknown')
            logger.admin_action(0, admin_user, 'backup_created', 'system', {
                'backup_path': backup_path,
                'timestamp': timestamp
            })
            
            return jsonify({
                'success': True,
                'message': 'Yedekleme başarılı',
                'backup_path': backup_path,
                'timestamp': timestamp
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Yedekleme başarısız'
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@settings_bp.route('/api/settings/test-connection', methods=['POST'])
def api_test_connections():
    """Sistem bağlantılarını test et API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        database = Database()
        security = SecurityManager(config)
        
        # Test sonuçları
        test_results = {
            'database': database.test_connection(),
            'security_system': security.test_security_system(),
            'config_validation': config.validate()
        }
        
        # OCR testi
        try:
            from bot.ocr_engine import OCREngine
            ocr = OCREngine(config)
            test_results['ocr_engine'] = await ocr.test_connection()
        except Exception as e:
            test_results['ocr_engine'] = False
            test_results['ocr_error'] = str(e)
        
        # Image memory testi
        try:
            from bot.image_memory import ImageMemory
            memory = ImageMemory()
            test_results['image_memory'] = memory.test_system()
        except Exception as e:
            test_results['image_memory'] = False
            test_results['memory_error'] = str(e)
        
        # Genel durum
        all_passed = all(result for key, result in test_results.items() 
                        if not key.endswith('_error'))
        
        return jsonify({
            'success': True,
            'all_tests_passed': all_passed,
            'test_results': test_results,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })