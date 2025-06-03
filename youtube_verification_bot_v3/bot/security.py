# bot/security.py
import hashlib
import json
import os
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from threading import Lock
import ipaddress
import base64
from collections import defaultdict, deque
import asyncio

from utils.logger import Logger
from utils.config import Config

class SecurityManager:
    """Gelişmiş güvenlik yönetim sistemi"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger()
        self.data_dir = "data"
        self.lock = Lock()
        
        # Dosya yolları
        self.security_config_file = os.path.join(self.data_dir, "security_config.json")
        self.rate_limits_file = os.path.join(self.data_dir, "rate_limits.json")
        self.security_events_file = os.path.join(self.data_dir, "security_events.json")
        self.blacklist_file = os.path.join(self.data_dir, "blacklist.json")
        self.whitelist_file = os.path.join(self.data_dir, "whitelist.json")
        self.suspicious_users_file = os.path.join(self.data_dir, "suspicious_users.json")
        
        # Memory-based tracking
        self.rate_limit_memory = defaultdict(deque)
        self.failed_attempts = defaultdict(int)
        self.suspicious_patterns = defaultdict(list)
        self.session_tracking = {}
        
        # Güvenlik ayarları
        self.security_rules = {
            'rate_limit': {
                'max_requests': config.get('RATE_LIMIT_REQUESTS', 3),
                'time_window': config.get('RATE_LIMIT_WINDOW', 300),  # 5 dakika
                'cooldown_period': 600,  # 10 dakika ceza
                'progressive_penalty': True
            },
            'file_validation': {
                'max_file_size': config.get('MAX_FILE_SIZE', 15728640),  # 15MB
                'allowed_extensions': config.get('ALLOWED_EXTENSIONS', ['png', 'jpg', 'jpeg', 'gif', 'webp']),
                'min_dimensions': (400, 300),
                'max_dimensions': (8000, 8000),
                'scan_for_malware': True
            },
            'content_filtering': {
                'detect_nsfw': False,  # NSFW detection (gelecekte)
                'detect_spam_text': True,
                'filter_suspicious_urls': True,
                'block_known_scams': True
            },
            'behavioral_analysis': {
                'track_user_patterns': True,
                'detect_automation': True,
                'analyze_submission_timing': True,
                'flag_unusual_activity': True
            },
            'anti_spam': {
                'max_daily_attempts': 10,
                'duplicate_submission_threshold': 3,
                'rapid_fire_threshold': 5,  # 5 submissions in 1 minute
                'text_similarity_threshold': 0.8
            }
        }
        
        # Şüpheli aktivite tespit algoritmaları
        self.suspicious_indicators = {
            'rapid_submissions': {'weight': 0.8, 'threshold': 5},
            'multiple_failures': {'weight': 0.7, 'threshold': 3},
            'unusual_timing': {'weight': 0.5, 'threshold': 2},
            'duplicate_content': {'weight': 0.9, 'threshold': 2},
            'automated_behavior': {'weight': 0.8, 'threshold': 3},
            'vpn_usage': {'weight': 0.3, 'threshold': 1},
            'suspicious_filenames': {'weight': 0.6, 'threshold': 2}
        }
        
        self.ensure_security_files()
        self.load_security_data()
    
    def ensure_security_files(self):
        """Güvenlik dosyalarını oluştur"""
        os.makedirs(self.data_dir, exist_ok=True)
        
        default_files = {
            self.security_config_file: self.security_rules,
            self.rate_limits_file: {},
            self.security_events_file: [],
            self.blacklist_file: {
                'user_ids': [],
                'ip_addresses': [],
                'file_hashes': [],
                'domains': [],
                'patterns': []
            },
            self.whitelist_file: {
                'user_ids': [],
                'ip_addresses': [],
                'trusted_domains': []
            },
            self.suspicious_users_file: {}
        }
        
        for file_path, default_data in default_files.items():
            if not os.path.exists(file_path):
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(default_data, f, indent=2, ensure_ascii=False)
                except Exception as e:
                    self.logger.error(f"Güvenlik dosyası oluşturma hatası {file_path}: {str(e)}")
    
    def load_security_data(self):
        """Güvenlik verilerini yükle"""
        try:
            self.logger.info("Güvenlik sistemi başlatılıyor...")
            
            # Güvenlik kurallarını yükle
            security_config = self.load_json(self.security_config_file)
            if security_config:
                self.security_rules.update(security_config)
            
            # Blacklist/Whitelist yükle
            self.blacklist = self.load_json(self.blacklist_file)
            self.whitelist = self.load_json(self.whitelist_file)
            
            # Şüpheli kullanıcıları yükle
            self.suspicious_users = self.load_json(self.suspicious_users_file)
            
            self.logger.info("Güvenlik sistemi başarıyla yüklendi")
            
        except Exception as e:
            self.logger.error(f"Güvenlik veri yükleme hatası: {str(e)}")
    
    def load_json(self, file_path: str, default: Any = None) -> Any:
        """JSON dosyası yükle"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return default or {}
        except Exception as e:
            self.logger.error(f"JSON yükleme hatası {file_path}: {str(e)}")
            return default or {}
    
    def save_json(self, file_path: str, data: Any):
        """JSON dosyası kaydet"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"JSON kaydetme hatası {file_path}: {str(e)}")
    
    # Rate Limiting
    def is_rate_limited(self, user_id: int) -> bool:
        """Rate limit kontrolü"""
        try:
            with self.lock:
                current_time = time.time()
                time_window = self.security_rules['rate_limit']['time_window']
                max_requests = self.security_rules['rate_limit']['max_requests']
                
                # Kullanıcının istek geçmişini al
                user_requests = self.rate_limit_memory[user_id]
                
                # Eski istekleri temizle
                while user_requests and current_time - user_requests[0] > time_window:
                    user_requests.popleft()
                
                # Rate limit kontrolü
                if len(user_requests) >= max_requests:
                    # Progressive penalty uygula
                    if self.security_rules['rate_limit']['progressive_penalty']:
                        penalty_count = self.failed_attempts[user_id]
                        cooldown = self.security_rules['rate_limit']['cooldown_period'] * (2 ** penalty_count)
                        cooldown = min(cooldown, 3600)  # Maksimum 1 saat
                    else:
                        cooldown = self.security_rules['rate_limit']['cooldown_period']
                    
                    # Son istek zamanını kontrol et
                    last_request_time = user_requests[-1] if user_requests else 0
                    if current_time - last_request_time < cooldown:
                        self.failed_attempts[user_id] += 1
                        
                        # Güvenlik olayı kaydet
                        self.log_security_event(user_id, 'rate_limit_exceeded', {
                            'requests_in_window': len(user_requests),
                            'max_allowed': max_requests,
                            'cooldown_period': cooldown,
                            'penalty_count': self.failed_attempts[user_id]
                        })
                        
                        return True
                
                # Yeni isteği ekle
                user_requests.append(current_time)
                
                # Başarılı istek, penalty sayacını sıfırla
                if user_id in self.failed_attempts:
                    self.failed_attempts[user_id] = max(0, self.failed_attempts[user_id] - 1)
                
                return False
                
        except Exception as e:
            self.logger.error(f"Rate limit kontrolü hatası: {str(e)}", user_id=user_id)
            return False
    
    def cleanup_rate_limits(self):
        """Eski rate limit kayıtlarını temizle"""
        try:
            with self.lock:
                current_time = time.time()
                cleanup_threshold = 3600  # 1 saat
                
                # Memory temizliği
                users_to_remove = []
                for user_id, requests in self.rate_limit_memory.items():
                    # Eski istekleri temizle
                    while requests and current_time - requests[0] > cleanup_threshold:
                        requests.popleft()
                    
                    # Boş kuyruğu kaldır
                    if not requests:
                        users_to_remove.append(user_id)
                
                for user_id in users_to_remove:
                    del self.rate_limit_memory[user_id]
                
                # Failed attempts temizliği
                for user_id in list(self.failed_attempts.keys()):
                    if self.failed_attempts[user_id] <= 0:
                        del self.failed_attempts[user_id]
                
                if users_to_remove:
                    self.logger.debug(f"Rate limit temizlik: {len(users_to_remove)} kullanıcı temizlendi")
                
        except Exception as e:
            self.logger.error(f"Rate limit temizlik hatası: {str(e)}")
    
    # Dosya Doğrulama
    def validate_file(self, attachment) -> bool:
        """Dosya güvenlik doğrulaması"""
        try:
            filename = attachment.filename.lower()
            file_size = attachment.size
            
            # Dosya boyutu kontrolü
            max_size = self.security_rules['file_validation']['max_file_size']
            if file_size > max_size:
                self.log_security_event(None, 'file_too_large', {
                    'filename': filename,
                    'size': file_size,
                    'max_allowed': max_size
                })
                return False
            
            # Dosya uzantısı kontrolü
            allowed_extensions = self.security_rules['file_validation']['allowed_extensions']
            file_extension = filename.split('.')[-1] if '.' in filename else ''
            
            if file_extension not in allowed_extensions:
                self.log_security_event(None, 'invalid_file_extension', {
                    'filename': filename,
                    'extension': file_extension,
                    'allowed_extensions': allowed_extensions
                })
                return False
            
            # Şüpheli dosya adı kontrolü
            if self.is_suspicious_filename(filename):
                self.log_security_event(None, 'suspicious_filename', {
                    'filename': filename
                })
                return False
            
            # Blacklist kontrolü
            file_hash = self.calculate_file_hash(attachment.url)
            if file_hash in self.blacklist.get('file_hashes', []):
                self.log_security_event(None, 'blacklisted_file', {
                    'filename': filename,
                    'file_hash': file_hash
                })
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Dosya doğrulama hatası: {str(e)}")
            return False
    
    def is_suspicious_filename(self, filename: str) -> bool:
        """Şüpheli dosya adı kontrolü"""
        suspicious_patterns = [
            r'script\.png',  # Script uzantısı gizlenmiş
            r'\.exe\.png',   # Executable gizlenmiş
            r'\.scr\.',      # Screensaver
            r'\.bat\.',      # Batch file
            r'malware',      # Açık malware ismi
            r'virus',        # Virus ismi
            r'hack',         # Hack kelimesi
            r'exploit',      # Exploit kelimesi
            r'\.php\.',      # PHP file gizlenmiş
            r'\.js\.',       # JavaScript gizlenmiş
            r'payload',      # Payload kelimesi
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                return True
        
        return False
    
    def calculate_file_hash(self, file_url: str) -> str:
        """Dosya hash hesapla"""
        try:
            import requests
            response = requests.get(file_url, timeout=10)
            if response.status_code == 200:
                return hashlib.sha256(response.content).hexdigest()
        except:
            pass
        return ""
    
    def scan_file_for_malware(self, file_data: bytes) -> bool:
        """Basit malware tarama (genişletilebilir)"""
        try:
            # Basit signature tabanlı kontrol
            malware_signatures = [
                b'MZ',  # PE header (executable)
                b'<script',  # JavaScript
                b'<?php',  # PHP
                b'eval(',  # Eval fonksiyonu
                b'exec(',  # Exec fonksiyonu
                b'system(',  # System komutları
            ]
            
            for signature in malware_signatures:
                if signature in file_data:
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Malware tarama hatası: {str(e)}")
            return False
    
    # Davranış Analizi
    def analyze_user_behavior(self, user_id: int, action: str, metadata: Dict = None) -> Dict[str, any]:
        """Kullanıcı davranış analizi"""
        try:
            current_time = datetime.now()
            
            # Kullanıcı session tracking
            if user_id not in self.session_tracking:
                self.session_tracking[user_id] = {
                    'first_seen': current_time.isoformat(),
                    'last_activity': current_time.isoformat(),
                    'actions': [],
                    'patterns': {},
                    'suspicious_score': 0
                }
            
            session = self.session_tracking[user_id]
            session['last_activity'] = current_time.isoformat()
            
            # Aksiyon kaydet
            action_record = {
                'action': action,
                'timestamp': current_time.isoformat(),
                'metadata': metadata or {}
            }
            session['actions'].append(action_record)
            
            # Son 100 aksiyonu tut
            if len(session['actions']) > 100:
                session['actions'] = session['actions'][-100:]
            
            # Şüpheli davranış analizi
            suspicious_score = 0
            detected_patterns = []
            
            # Rapid fire analysis (hızlı ardışık işlemler)
            recent_actions = [
                a for a in session['actions'] 
                if (current_time - datetime.fromisoformat(a['timestamp'])).seconds < 60
            ]
            
            if len(recent_actions) >= self.suspicious_indicators['rapid_submissions']['threshold']:
                suspicious_score += self.suspicious_indicators['rapid_submissions']['weight']
                detected_patterns.append('rapid_submissions')
            
            # Timing pattern analysis (zamanlama analizi)
            if len(session['actions']) >= 5:
                intervals = []
                for i in range(1, min(6, len(session['actions']))):
                    prev_time = datetime.fromisoformat(session['actions'][-i-1]['timestamp'])
                    curr_time = datetime.fromisoformat(session['actions'][-i]['timestamp'])
                    intervals.append((curr_time - prev_time).total_seconds())
                
                # Çok düzenli aralıklar (bot davranışı)
                if len(set([round(interval) for interval in intervals])) == 1:
                    suspicious_score += self.suspicious_indicators['automated_behavior']['weight']
                    detected_patterns.append('automated_behavior')
            
            # Failure pattern analysis
            failed_actions = [
                a for a in session['actions'][-10:] 
                if a.get('metadata', {}).get('status') == 'failed'
            ]
            
            if len(failed_actions) >= self.suspicious_indicators['multiple_failures']['threshold']:
                suspicious_score += self.suspicious_indicators['multiple_failures']['weight']
                detected_patterns.append('multiple_failures')
            
            # Unusual timing (gece saatleri, hafta sonu yoğunluğu)
            hour = current_time.hour
            if 2 <= hour <= 6:  # Gece 02:00 - 06:00 arası
                suspicious_score += self.suspicious_indicators['unusual_timing']['weight'] * 0.5
                detected_patterns.append('unusual_timing_night')
            
            # Şüpheli skor güncelle
            session['suspicious_score'] = min(suspicious_score, 10)  # Maksimum 10
            session['patterns'] = {
                'detected': detected_patterns,
                'last_analysis': current_time.isoformat(),
                'score': suspicious_score
            }
            
            # Eşik değeri aşıldıysa şüpheli kullanıcı olarak işaretle
            if suspicious_score >= 3:
                self.mark_user_suspicious(user_id, detected_patterns, suspicious_score)
            
            return {
                'suspicious_score': suspicious_score,
                'detected_patterns': detected_patterns,
                'is_suspicious': suspicious_score >= 3,
                'session_duration': (current_time - datetime.fromisoformat(session['first_seen'])).total_seconds(),
                'total_actions': len(session['actions'])
            }
            
        except Exception as e:
            self.logger.error(f"Davranış analizi hatası: {str(e)}", user_id=user_id)
            return {'suspicious_score': 0, 'detected_patterns': [], 'is_suspicious': False}
    
    def mark_user_suspicious(self, user_id: int, patterns: List[str], score: float):
        """Kullanıcıyı şüpheli olarak işaretle"""
        try:
            with self.lock:
                if str(user_id) not in self.suspicious_users:
                    self.suspicious_users[str(user_id)] = {
                        'first_flagged': datetime.now().isoformat(),
                        'flag_count': 0,
                        'patterns': [],
                        'scores': [],
                        'status': 'monitoring'
                    }
                
                user_record = self.suspicious_users[str(user_id)]
                user_record['flag_count'] += 1
                user_record['last_flagged'] = datetime.now().isoformat()
                user_record['patterns'].extend(patterns)
                user_record['scores'].append(score)
                
                # Unique patterns
                user_record['patterns'] = list(set(user_record['patterns']))
                
                # Son 10 skoru tut
                if len(user_record['scores']) > 10:
                    user_record['scores'] = user_record['scores'][-10:]
                
                # Status güncelle
                avg_score = sum(user_record['scores']) / len(user_record['scores'])
                if avg_score >= 5 or user_record['flag_count'] >= 5:
                    user_record['status'] = 'high_risk'
                elif avg_score >= 3 or user_record['flag_count'] >= 3:
                    user_record['status'] = 'medium_risk'
                
                self.save_json(self.suspicious_users_file, self.suspicious_users)
                
                # Güvenlik olayı kaydet
                self.log_security_event(user_id, 'user_flagged_suspicious', {
                    'patterns': patterns,
                    'score': score,
                    'flag_count': user_record['flag_count'],
                    'status': user_record['status']
                })
                
        except Exception as e:
            self.logger.error(f"Şüpheli kullanıcı işaretleme hatası: {str(e)}", user_id=user_id)
    
    def is_user_suspicious(self, user_id: int) -> Dict[str, any]:
        """Kullanıcı şüpheli mi kontrol et"""
        try:
            user_record = self.suspicious_users.get(str(user_id))
            
            if not user_record:
                return {'is_suspicious': False, 'risk_level': 'none'}
            
            return {
                'is_suspicious': True,
                'risk_level': user_record.get('status', 'low_risk'),
                'flag_count': user_record.get('flag_count', 0),
                'patterns': user_record.get('patterns', []),
                'last_flagged': user_record.get('last_flagged'),
                'average_score': sum(user_record.get('scores', [0])) / len(user_record.get('scores', [1]))
            }
            
        except Exception as e:
            self.logger.error(f"Şüpheli kullanıcı kontrolü hatası: {str(e)}", user_id=user_id)
            return {'is_suspicious': False, 'risk_level': 'error'}
    
    # Content Filtering
    def filter_suspicious_content(self, text: str) -> Dict[str, any]:
        """Şüpheli içerik filtrele"""
        try:
            suspicious_indicators = []
            risk_score = 0
            
            # Spam kelimeler
            spam_patterns = [
                r'(?i)\b(?:free\s+money|bedava\s+para|ücretsiz\s+para)\b',
                r'(?i)\b(?:click\s+here|buraya\s+tıkla|hemen\s+tıkla)\b',
                r'(?i)\b(?:limited\s+time|sınırlı\s+süre|son\s+fırsat)\b',
                r'(?i)\b(?:guaranteed|garanti|kesin\s+kazanç)\b',
                r'(?i)\b(?:winner|kazanan|seçildin)\b'
            ]
            
            for pattern in spam_patterns:
                if re.search(pattern, text):
                    suspicious_indicators.append(f'spam_pattern: {pattern}')
                    risk_score += 0.3
            
            # Şüpheli URL'ler
            url_pattern = r'(?i)https?://[^\s]+'
            urls = re.findall(url_pattern, text)
            
            for url in urls:
                if self.is_suspicious_url(url):
                    suspicious_indicators.append(f'suspicious_url: {url}')
                    risk_score += 0.5
            
            # Excessive capitalization
            caps_ratio = len(re.findall(r'[A-Z]', text)) / len(text) if text else 0
            if caps_ratio > 0.3:  # %30'dan fazla büyük harf
                suspicious_indicators.append('excessive_capitalization')
                risk_score += 0.2
            
            # Repeating characters/words
            if re.search(r'(.)\1{4,}', text):  # Aynı karakter 5+ kez
                suspicious_indicators.append('repeating_characters')
                risk_score += 0.2
            
            # Phone numbers (potansiyel spam)
            phone_pattern = r'(?:\+90|0)?\s*\d{3}\s*\d{3}\s*\d{2}\s*\d{2}'
            if re.search(phone_pattern, text):
                suspicious_indicators.append('contains_phone_number')
                risk_score += 0.1
            
            return {
                'is_suspicious': risk_score >= 0.5,
                'risk_score': min(risk_score, 1.0),
                'indicators': suspicious_indicators,
                'detected_urls': urls,
                'analysis': {
                    'caps_ratio': caps_ratio,
                    'text_length': len(text),
                    'word_count': len(text.split())
                }
            }
            
        except Exception as e:
            self.logger.error(f"İçerik filtreleme hatası: {str(e)}")
            return {'is_suspicious': False, 'risk_score': 0, 'indicators': []}
    
    def is_suspicious_url(self, url: str) -> bool:
        """URL şüpheli mi kontrol et"""
        try:
            # Blacklist kontrolü
            for domain in self.blacklist.get('domains', []):
                if domain in url.lower():
                    return True
            
            # Şüpheli URL patterns
            suspicious_patterns = [
                r'bit\.ly|tinyurl|t\.co',  # URL shorteners
                r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IP adresi
                r'\.tk|\.ml|\.ga|\.cf',  # Ücretsiz domainler
                r'phishing|scam|fake',  # Açık şüpheli kelimeler
                r'discord-?nitro',  # Sahte Discord Nitro
                r'free-?discord',  # Sahte Discord
                r'steam-?gift',  # Sahte Steam
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"URL kontrol hatası: {str(e)}")
            return False
    
    # Blacklist/Whitelist Management
    def add_to_blacklist(self, item_type: str, value: str, reason: str = None):
        """Blacklist'e ekle"""
        try:
            with self.lock:
                if item_type not in self.blacklist:
                    self.blacklist[item_type] = []
                
                if value not in self.blacklist[item_type]:
                    self.blacklist[item_type].append(value)
                    self.save_json(self.blacklist_file, self.blacklist)
                    
                    self.log_security_event(None, 'blacklist_addition', {
                        'type': item_type,
                        'value': value,
                        'reason': reason
                    })
                    
                    self.logger.warning(f"Blacklist'e eklendi: {item_type} = {value}")
                
        except Exception as e:
            self.logger.error(f"Blacklist ekleme hatası: {str(e)}")
    
    def remove_from_blacklist(self, item_type: str, value: str):
        """Blacklist'ten kaldır"""
        try:
            with self.lock:
                if item_type in self.blacklist and value in self.blacklist[item_type]:
                    self.blacklist[item_type].remove(value)
                    self.save_json(self.blacklist_file, self.blacklist)
                    
                    self.log_security_event(None, 'blacklist_removal', {
                        'type': item_type,
                        'value': value
                    })
                    
                    self.logger.info(f"Blacklist'ten kaldırıldı: {item_type} = {value}")
                
        except Exception as e:
            self.logger.error(f"Blacklist kaldırma hatası: {str(e)}")
    
    def is_blacklisted(self, item_type: str, value: str) -> bool:
        """Blacklist kontrolü"""
        try:
            return value in self.blacklist.get(item_type, [])
        except Exception as e:
            self.logger.error(f"Blacklist kontrol hatası: {str(e)}")
            return False
    
    # Security Event Logging
    def log_security_event(self, user_id: Optional[int], event_type: str, details: Dict = None):
        """Güvenlik olayı kaydet"""
        try:
            with self.lock:
                events = self.load_json(self.security_events_file, [])
                
                event = {
                    'id': f"sec_{int(time.time() * 1000)}",
                    'timestamp': datetime.now().isoformat(),
                    'user_id': user_id,
                    'event_type': event_type,
                    'severity': self.get_event_severity(event_type),
                    'details': details or {},
                    'resolved': False,
                    'auto_action': self.get_auto_action(event_type)
                }
                
                events.append(event)
                
                # Son 10000 olayı tut
                if len(events) > 10000:
                    events = events[-10000:]
                
                self.save_json(self.security_events_file, events)
                
                # Critical olaylarda anında aksiyon al
                if event['severity'] == 'critical':
                    self.handle_critical_security_event(event)
                
                self.logger.security(f"Güvenlik olayı: {event_type}", details, user_id)
                
        except Exception as e:
            self.logger.error(f"Güvenlik olayı kaydetme hatası: {str(e)}")
    
    def get_event_severity(self, event_type: str) -> str:
        """Olay şiddet seviyesi"""
        severity_map = {
            'rate_limit_exceeded': 'low',
            'file_too_large': 'low',
            'invalid_file_extension': 'low',
            'suspicious_filename': 'medium',
            'blacklisted_file': 'high',
            'user_flagged_suspicious': 'medium',
            'rapid_submissions': 'medium',
            'multiple_failures': 'medium',
            'automated_behavior': 'high',
            'malware_detected': 'critical',
            'exploit_attempt': 'critical',
            'security_breach': 'critical'
        }
        
        return severity_map.get(event_type, 'low')
    
    def get_auto_action(self, event_type: str) -> str:
        """Otomatik aksiyon belirle"""
        action_map = {
            'rate_limit_exceeded': 'cooldown',
            'blacklisted_file': 'block',
            'malware_detected': 'quarantine',
            'automated_behavior': 'flag_user',
            'exploit_attempt': 'blacklist_user'
        }
        
        return action_map.get(event_type, 'log_only')
    
    def handle_critical_security_event(self, event: Dict):
        """Kritik güvenlik olayı işle"""
        try:
            user_id = event.get('user_id')
            event_type = event['event_type']
            
            if event_type == 'malware_detected' and user_id:
                # Kullanıcıyı otomatik blacklist'e al
                self.add_to_blacklist('user_ids', str(user_id), 'Malware detection')
                
            elif event_type == 'exploit_attempt' and user_id:
                # Kullanıcıyı blacklist'e al ve tüm oturumlarını sonlandır
                self.add_to_blacklist('user_ids', str(user_id), 'Exploit attempt')
                if user_id in self.session_tracking:
                    del self.session_tracking[user_id]
            
            # Emergency notification (gelecekte webhook/email)
            self.logger.error(f"CRITICAL SECURITY EVENT: {event_type} - User: {user_id}")
            
        except Exception as e:
            self.logger.error(f"Kritik olay işleme hatası: {str(e)}")
    
    # Suspicious Activity Detection
    async def check_suspicious_activity(self):
        """Şüpheli aktivite kontrolü (periyodik)"""
        try:
            current_time = datetime.now()
            
            # Son 1 saatteki olayları analiz et
            events = self.load_json(self.security_events_file, [])
            recent_events = [
                e for e in events 
                if (current_time - datetime.fromisoformat(e['timestamp'])).seconds < 3600
            ]
            
            # Pattern detection
            user_event_counts = defaultdict(int)
            event_type_counts = defaultdict(int)
            
            for event in recent_events:
                user_id = event.get('user_id')
                if user_id:
                    user_event_counts[user_id] += 1
                event_type_counts[event['event_type']] += 1
            
            # Anormal aktivite tespiti
            for user_id, count in user_event_counts.items():
                if count >= 10:  # 1 saatte 10+ güvenlik olayı
                    self.mark_user_suspicious(user_id, ['excessive_security_events'], count)
            
            # Event type spike detection
            for event_type, count in event_type_counts.items():
                if count >= 20:  # 1 saatte 20+ aynı tip olay
                    self.log_security_event(None, 'event_spike_detected', {
                        'event_type': event_type,
                        'count': count,
                        'timeframe': '1_hour'
                    })
            
        except Exception as e:
            self.logger.error(f"Şüpheli aktivite kontrolü hatası: {str(e)}")
    
    # Statistics and Reporting
    def get_security_statistics(self) -> Dict[str, any]:
        """Güvenlik istatistikleri"""
        try:
            events = self.load_json(self.security_events_file, [])
            
            # Son 24 saat
            last_24h = datetime.now() - timedelta(hours=24)
            recent_events = [
                e for e in events 
                if datetime.fromisoformat(e['timestamp']) > last_24h
            ]
            
            # Event type distribution
            event_types = defaultdict(int)
            severity_counts = defaultdict(int)
            
            for event in recent_events:
                event_types[event['event_type']] += 1
                severity_counts[event['severity']] += 1
            
            # Suspicious users stats
            suspicious_count = len(self.suspicious_users)
            high_risk_count = len([
                u for u in self.suspicious_users.values() 
                if u.get('status') == 'high_risk'
            ])
            
            # Rate limit stats
            current_rate_limited = len(self.rate_limit_memory)
            
            return {
                'total_security_events': len(events),
                'events_last_24h': len(recent_events),
                'event_type_distribution': dict(event_types),
                'severity_distribution': dict(severity_counts),
                'suspicious_users': {
                    'total': suspicious_count,
                    'high_risk': high_risk_count,
                    'medium_risk': len([
                        u for u in self.suspicious_users.values() 
                        if u.get('status') == 'medium_risk'
                    ]),
                    'monitoring': len([
                        u for u in self.suspicious_users.values() 
                        if u.get('status') == 'monitoring'
                    ])
                },
                'rate_limiting': {
                    'currently_limited': current_rate_limited,
                    'failed_attempts': len(self.failed_attempts)
                },
                'blacklist_sizes': {
                    item_type: len(items) 
                    for item_type, items in self.blacklist.items()
                },
                'system_status': 'active',
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Güvenlik istatistik hatası: {str(e)}")
            return {'system_status': 'error', 'error': str(e)}
    
    def export_security_report(self, output_file: str, days: int = 7):
        """Güvenlik raporu dışa aktar"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            
            events = self.load_json(self.security_events_file, [])
            filtered_events = [
                e for e in events 
                if datetime.fromisoformat(e['timestamp']) > cutoff_date
            ]
            
            report = {
                'generated_at': datetime.now().isoformat(),
                'period_days': days,
                'summary': self.get_security_statistics(),
                'events': filtered_events,
                'suspicious_users': self.suspicious_users,
                'blacklist': self.blacklist,
                'whitelist': self.whitelist
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.logger.success(f"Güvenlik raporu oluşturuldu: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Güvenlik raporu oluşturma hatası: {str(e)}")
    
    def test_security_system(self) -> bool:
        """Güvenlik sistemi testi"""
        try:
            # Rate limiting testi
            test_user_id = 999999
            
            # Normal istek
            if self.is_rate_limited(test_user_id):
                return False
            
            # Rate limit test
            for _ in range(10):
                self.is_rate_limited(test_user_id)
            
            # Şimdi rate limited olmalı
            if not self.is_rate_limited(test_user_id):
                return False
            
            # Temizlik
            if test_user_id in self.rate_limit_memory:
                del self.rate_limit_memory[test_user_id]
            if test_user_id in self.failed_attempts:
                del self.failed_attempts[test_user_id]
            
            return True
            
        except Exception as e:
            self.logger.error(f"Güvenlik sistemi test hatası: {str(e)}")
            return False