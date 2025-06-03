# web/routes/users.py
from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for, flash
from datetime import datetime, timedelta
import json
from typing import Dict, List, Any, Optional

from utils.logger import Logger
from utils.config import Config
from bot.database import Database
from bot.image_memory import ImageMemory
from bot.security import SecurityManager

users_bp = Blueprint('users', __name__)

class UserManager:
    """Kullanıcı yönetim sınıfı"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger()
        self.database = Database()
        self.image_memory = ImageMemory()
        self.security = SecurityManager(config)
        
        # Kullanıcı durumları
        self.user_statuses = {
            'verified': 'Doğrulanmış',
            'pending': 'Beklemede',
            'rejected': 'Reddedilmiş',
            'suspicious': 'Şüpheli',
            'banned': 'Yasaklı'
        }
        
        # Risk seviyeleri
        self.risk_levels = {
            'none': {'label': 'Güvenli', 'color': 'success', 'icon': 'fas fa-shield-alt'},
            'low': {'label': 'Düşük Risk', 'color': 'info', 'icon': 'fas fa-info-circle'},
            'medium': {'label': 'Orta Risk', 'color': 'warning', 'icon': 'fas fa-exclamation-triangle'},
            'high': {'label': 'Yüksek Risk', 'color': 'danger', 'icon': 'fas fa-exclamation-circle'},
            'critical': {'label': 'Kritik Risk', 'color': 'dark', 'icon': 'fas fa-skull-crossbones'}
        }
    
    def get_user_list(self, status_filter: str = 'all', risk_filter: str = 'all', 
                     search_query: str = None, sort_by: str = 'last_activity', 
                     sort_order: str = 'desc', limit: int = 100) -> Dict[str, Any]:
        """Kullanıcı listesini getir"""
        try:
            # Temel verileri al
            verified_users = self.database.get_all_verified_users()
            suspicious_users = self.security.load_json(self.security.suspicious_users_file, {})
            user_attempts = self.database.load_json(self.database.user_attempts_file, {})
            pending_verifications = self.database.load_json(self.database.pending_verifications_file, {})
            
            user_list = []
            
            # Doğrulanmış kullanıcıları işle
            for user_id, user_data in verified_users.items():
                user_info = self.build_user_info(
                    user_id, user_data, suspicious_users, user_attempts, 'verified'
                )
                user_list.append(user_info)
            
            # Bekleyen kullanıcıları işle
            pending_users = {}
            for verification in pending_verifications.values():
                if verification.get('status') == 'pending':
                    user_id = str(verification.get('user_id'))
                    if user_id not in verified_users:  # Zaten doğrulanmış değilse
                        if user_id not in pending_users:
                            pending_users[user_id] = {
                                'username': verification.get('username', f'User_{user_id}'),
                                'submitted_at': verification.get('submitted_at'),
                                'attempts': 1
                            }
                        else:
                            pending_users[user_id]['attempts'] += 1
            
            for user_id, user_data in pending_users.items():
                user_info = self.build_user_info(
                    user_id, user_data, suspicious_users, user_attempts, 'pending'
                )
                user_list.append(user_info)
            
            # Sadece şüpheli olanları ekle (doğrulanmamış)
            for user_id, suspicious_data in suspicious_users.items():
                if user_id not in verified_users and user_id not in pending_users:
                    user_info = self.build_user_info(
                        user_id, {'username': f'User_{user_id}'}, 
                        suspicious_users, user_attempts, 'suspicious'
                    )
                    user_list.append(user_info)
            
            # Filtreleme uygula
            filtered_users = self.apply_filters(user_list, status_filter, risk_filter, search_query)
            
            # Sıralama uygula
            sorted_users = self.apply_sorting(filtered_users, sort_by, sort_order)
            
            # Limit uygula
            paginated_users = sorted_users[:limit]
            
            # İstatistikler hesapla
            stats = self.calculate_user_stats(user_list)
            
            return {
                'users': paginated_users,
                'stats': stats,
                'total_count': len(user_list),
                'filtered_count': len(filtered_users),
                'filters_applied': {
                    'status': status_filter,
                    'risk': risk_filter,
                    'search': search_query,
                    'sort_by': sort_by,
                    'sort_order': sort_order
                }
            }
            
        except Exception as e:
            self.logger.error(f"Kullanıcı listesi hatası: {str(e)}")
            return {'users': [], 'stats': {}, 'total_count': 0, 'filtered_count': 0}
    
    def build_user_info(self, user_id: str, user_data: Dict, suspicious_users: Dict, 
                       user_attempts: Dict, status: str) -> Dict[str, Any]:
        """Kullanıcı bilgilerini oluştur"""
        user_id_int = int(user_id)
        
        # Şüpheli kullanıcı bilgisi
        suspicious_info = suspicious_users.get(user_id, {})
        risk_level = suspicious_info.get('status', 'none')
        
        # Deneme bilgisi
        attempt_info = user_attempts.get(user_id, {})
        
        # Resim geçmişi
        image_history = self.image_memory.get_user_image_history(user_id_int)
        
        # Son aktivite
        last_activity = (
            user_data.get('last_updated') or 
            user_data.get('verified_at') or 
            attempt_info.get('last_attempt') or
            suspicious_info.get('last_flagged')
        )
        
        return {
            'user_id': user_id_int,
            'username': user_data.get('username', f'User_{user_id}'),
            'status': status,
            'verified_at': user_data.get('verified_at'),
            'verification_count': user_data.get('verification_count', 0),
            'security_score': user_data.get('security_score', 100),
            'risk_level': risk_level,
            'risk_info': self.risk_levels.get(risk_level, self.risk_levels['none']),
            'total_attempts': attempt_info.get('total_attempts', 0),
            'daily_attempts': attempt_info.get('daily_attempts', {}).get(
                datetime.now().strftime('%Y-%m-%d'), 0
            ),
            'suspicious_activity': suspicious_info.get('suspicious_activity', False),
            'flag_count': suspicious_info.get('flag_count', 0),
            'suspicious_patterns': suspicious_info.get('patterns', []),
            'last_activity': last_activity,
            'last_activity_formatted': self.format_relative_time(last_activity),
            'image_count': len(image_history),
            'manual_verification': user_data.get('manual_verification', False),
            'admin_notes': user_data.get('notes', []),
            'account_age': self.calculate_account_age(user_data.get('verified_at') or attempt_info.get('first_attempt')),
            'is_blacklisted': self.security.is_blacklisted('user_ids', user_id)
        }
    
    def apply_filters(self, users: List[Dict], status_filter: str, risk_filter: str, 
                     search_query: str) -> List[Dict]:
        """Filtreleri uygula"""
        filtered = users
        
        # Durum filtresi
        if status_filter != 'all':
            filtered = [u for u in filtered if u['status'] == status_filter]
        
        # Risk filtresi
        if risk_filter != 'all':
            filtered = [u for u in filtered if u['risk_level'] == risk_filter]
        
        # Arama filtresi
        if search_query:
            search_lower = search_query.lower()
            search_filtered = []
            
            for user in filtered:
                # Username'de ara
                if search_lower in user['username'].lower():
                    search_filtered.append(user)
                    continue
                
                # User ID'de ara
                if search_query.isdigit() and str(user['user_id']) == search_query:
                    search_filtered.append(user)
                    continue
                
                # Suspicious patterns'da ara
                patterns = user.get('suspicious_patterns', [])
                if any(search_lower in pattern.lower() for pattern in patterns):
                    search_filtered.append(user)
                    continue
            
            filtered = search_filtered
        
        return filtered
    
    def apply_sorting(self, users: List[Dict], sort_by: str, sort_order: str) -> List[Dict]:
        """Sıralama uygula"""
        reverse = sort_order == 'desc'
        
        if sort_by == 'username':
            return sorted(users, key=lambda x: x['username'].lower(), reverse=reverse)
        elif sort_by == 'verification_count':
            return sorted(users, key=lambda x: x['verification_count'], reverse=reverse)
        elif sort_by == 'security_score':
            return sorted(users, key=lambda x: x['security_score'], reverse=reverse)
        elif sort_by == 'total_attempts':
            return sorted(users, key=lambda x: x['total_attempts'], reverse=reverse)
        elif sort_by == 'risk_level':
            risk_order = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            return sorted(users, key=lambda x: risk_order.get(x['risk_level'], 0), reverse=reverse)
        elif sort_by == 'last_activity':
            return sorted(users, key=lambda x: x['last_activity'] or '', reverse=reverse)
        else:
            return users
    
    def calculate_user_stats(self, users: List[Dict]) -> Dict[str, Any]:
        """Kullanıcı istatistikleri"""
        if not users:
            return {}
        
        # Durum dağılımı
        status_counts = {}
        for user in users:
            status = user['status']
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Risk seviyesi dağılımı
        risk_counts = {}
        for user in users:
            risk = user['risk_level']
            risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        # Ortalama güvenlik skoru
        security_scores = [u['security_score'] for u in users if u['security_score'] > 0]
        avg_security_score = sum(security_scores) / len(security_scores) if security_scores else 0
        
        # Son 24 saatteki aktivite
        yesterday = datetime.now() - timedelta(days=1)
        recent_activity = 0
        
        for user in users:
            last_activity = user.get('last_activity')
            if last_activity:
                try:
                    activity_time = datetime.fromisoformat(last_activity)
                    if activity_time > yesterday:
                        recent_activity += 1
                except:
                    continue
        
        # En riskli kullanıcılar
        high_risk_users = [u for u in users if u['risk_level'] in ['high', 'critical']]
        
        return {
            'total_users': len(users),
            'status_distribution': status_counts,
            'risk_distribution': risk_counts,
            'avg_security_score': round(avg_security_score, 1),
            'recent_activity_24h': recent_activity,
            'high_risk_count': len(high_risk_users),
            'verified_rate': (status_counts.get('verified', 0) / len(users)) * 100 if users else 0,
            'top_risk_users': sorted(high_risk_users, key=lambda x: x['flag_count'], reverse=True)[:5]
        }
    
    def get_user_details(self, user_id: int) -> Dict[str, Any]:
        """Detaylı kullanıcı bilgisi"""
        try:
            # Temel kullanıcı verisi
            user_data = self.database.get_user_data(user_id)
            
            # Şüpheli aktivite bilgisi
            suspicious_info = self.security.is_user_suspicious(user_id)
            
            # Resim geçmişi
            image_history = self.image_memory.get_user_image_history(user_id)
            
            # Güvenlik olayları
            security_events = self.security.get_security_events(limit=50, user_id=user_id)
            
            # Doğrulama geçmişi
            verification_history = self.get_user_verification_history(user_id)
            
            # Admin aksiyonları
            admin_actions = [
                action for action in self.database.get_admin_actions(50)
                if action.get('target_user_id') == user_id
            ]
            
            # Davranış analizi
            behavior_analysis = self.analyze_user_behavior(user_id)
            
            return {
                'basic_info': user_data,
                'suspicious_info': suspicious_info,
                'image_history': image_history,
                'security_events': security_events,
                'verification_history': verification_history,
                'admin_actions': admin_actions,
                'behavior_analysis': behavior_analysis,
                'recommendations': self.generate_user_recommendations(user_id, user_data, suspicious_info)
            }
            
        except Exception as e:
            self.logger.error(f"Kullanıcı detay hatası: {str(e)}", user_id=user_id)
            return {}
    
    def get_user_verification_history(self, user_id: int) -> List[Dict]:
        """Kullanıcı doğrulama geçmişi"""
        try:
            pending_verifications = self.database.load_json(self.database.pending_verifications_file, {})
            
            user_verifications = []
            for verification in pending_verifications.values():
                if verification.get('user_id') == user_id:
                    user_verifications.append({
                        'submitted_at': verification.get('submitted_at'),
                        'status': verification.get('status', 'pending'),
                        'image_url': verification.get('image_url'),
                        'reviewed_at': verification.get('reviewed_at'),
                        'reviewed_by': verification.get('reviewed_by')
                    })
            
            # Tarihe göre sırala
            user_verifications.sort(key=lambda x: x.get('submitted_at', ''), reverse=True)
            
            return user_verifications
            
        except Exception as e:
            self.logger.error(f"Doğrulama geçmişi hatası: {str(e)}", user_id=user_id)
            return []
    
    def analyze_user_behavior(self, user_id: int) -> Dict[str, Any]:
        """Kullanıcı davranış analizi"""
        try:
            # Session tracking verisi
            session_data = self.security.session_tracking.get(user_id, {})
            
            if not session_data:
                return {'status': 'no_data'}
            
            actions = session_data.get('actions', [])
            patterns = session_data.get('patterns', {})
            
            # Aktivite analizi
            if actions:
                # Zaman aralıkları
                timestamps = [datetime.fromisoformat(a['timestamp']) for a in actions]
                if len(timestamps) > 1:
                    intervals = [(timestamps[i] - timestamps[i-1]).total_seconds() 
                               for i in range(1, len(timestamps))]
                    avg_interval = sum(intervals) / len(intervals)
                else:
                    avg_interval = 0
                
                # Aktivite yoğunluğu
                activity_intensity = len(actions) / max(1, (timestamps[-1] - timestamps[0]).total_seconds() / 3600)
                
                # En aktif saatler
                hour_activity = {}
                for ts in timestamps:
                    hour = ts.hour
                    hour_activity[hour] = hour_activity.get(hour, 0) + 1
                
                most_active_hour = max(hour_activity.items(), key=lambda x: x[1])[0] if hour_activity else None
            else:
                avg_interval = 0
                activity_intensity = 0
                most_active_hour = None
            
            return {
                'status': 'analyzed',
                'total_actions': len(actions),
                'avg_interval_seconds': round(avg_interval, 2),
                'activity_intensity_per_hour': round(activity_intensity, 2),
                'most_active_hour': most_active_hour,
                'detected_patterns': patterns.get('detected', []),
                'suspicious_score': patterns.get('score', 0),
                'session_duration': session_data.get('last_activity'),
                'first_seen': session_data.get('first_seen')
            }
            
        except Exception as e:
            self.logger.error(f"Davranış analizi hatası: {str(e)}", user_id=user_id)
            return {'status': 'error', 'error': str(e)}
    
    def generate_user_recommendations(self, user_id: int, user_data: Dict, 
                                    suspicious_info: Dict) -> List[Dict]:
        """Kullanıcı için öneriler oluştur"""
        recommendations = []
        
        # Risk seviyesine göre öneriler
        risk_level = suspicious_info.get('risk_level', 'none')
        
        if risk_level == 'high' or risk_level == 'critical':
            recommendations.append({
                'type': 'security',
                'priority': 'high',
                'title': 'Güvenlik İncelemesi',
                'description': 'Bu kullanıcı yüksek risk seviyesinde. Detaylı inceleme yapılmalı.',
                'action': 'investigate'
            })
        
        # Güvenlik skoruna göre
        security_score = user_data.get('security_score', 100)
        if security_score < 50:
            recommendations.append({
                'type': 'security',
                'priority': 'medium',
                'title': 'Güvenlik Skoru Düşük',
                'description': 'Kullanıcının güvenlik skoru normal seviyenin altında.',
                'action': 'monitor'
            })
        
        # Çok fazla deneme
        attempts = user_data.get('attempts', 0)
        if attempts > 10:
            recommendations.append({
                'type': 'behavior',
                'priority': 'medium',
                'title': 'Çok Fazla Deneme',
                'description': 'Kullanıcı çok fazla doğrulama denemesi yapmış.',
                'action': 'review_attempts'
            })
        
        # Şüpheli patterns
        if suspicious_info.get('is_suspicious'):
            patterns = suspicious_info.get('patterns', [])
            if 'automated_behavior' in patterns:
                recommendations.append({
                    'type': 'automation',
                    'priority': 'high',
                    'title': 'Otomatik Davranış',
                    'description': 'Bot benzeri davranış tespit edildi.',
                    'action': 'verify_human'
                })
        
        return recommendations
    
    def format_relative_time(self, timestamp: str) -> str:
        """Relative time formatı"""
        if not timestamp:
            return 'Bilinmiyor'
        
        try:
            dt = datetime.fromisoformat(timestamp)
            now = datetime.now()
            diff = now - dt
            
            if diff.days > 30:
                return f"{diff.days // 30} ay önce"
            elif diff.days > 0:
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
            return timestamp
    
    def calculate_account_age(self, first_activity: str) -> str:
        """Hesap yaşı hesapla"""
        if not first_activity:
            return 'Bilinmiyor'
        
        try:
            first_dt = datetime.fromisoformat(first_activity)
            now = datetime.now()
            diff = now - first_dt
            
            if diff.days > 365:
                years = diff.days // 365
                return f"{years} yıl"
            elif diff.days > 30:
                months = diff.days // 30
                return f"{months} ay"
            elif diff.days > 0:
                return f"{diff.days} gün"
            else:
                return "Yeni"
        except:
            return 'Bilinmiyor'

# Route tanımlamaları
@users_bp.route('/users')
def users():
    """Kullanıcı listesi sayfası"""
    try:
        config = Config()
        user_manager = UserManager(config)
        
        # URL parametrelerini al
        status_filter = request.args.get('status', 'all')
        risk_filter = request.args.get('risk', 'all')
        search_query = request.args.get('search', '')
        sort_by = request.args.get('sort_by', 'last_activity')
        sort_order = request.args.get('sort_order', 'desc')
        limit = int(request.args.get('limit', 100))
        
        # Kullanıcı listesini getir
        user_data = user_manager.get_user_list(
            status_filter=status_filter,
            risk_filter=risk_filter,
            search_query=search_query,
            sort_by=sort_by,
            sort_order=sort_order,
            limit=limit
        )
        
        return render_template('users.html',
            user_data=user_data,
            user_statuses=user_manager.user_statuses,
            risk_levels=user_manager.risk_levels,
            current_filters={
                'status': status_filter,
                'risk': risk_filter,
                'search': search_query,
                'sort_by': sort_by,
                'sort_order': sort_order,
                'limit': limit
            }
        )
        
    except Exception as e:
        logger = Logger()
        logger.error(f"Kullanıcı sayfası hatası: {str(e)}")
        return render_template('error.html', 
                             error_message="Kullanıcı sayfası yüklenirken hata oluştu")

@users_bp.route('/users/<int:user_id>')
def user_detail(user_id):
    """Kullanıcı detay sayfası"""
    try:
        config = Config()
        user_manager = UserManager(config)
        
        # Kullanıcı detaylarını getir
        user_details = user_manager.get_user_details(user_id)
        
        if not user_details:
            flash('Kullanıcı bulunamadı!', 'error')
            return redirect(url_for('users.users'))
        
        return render_template('user_detail.html',
            user_id=user_id,
            user_details=user_details
        )
        
    except Exception as e:
        logger = Logger()
        logger.error(f"Kullanıcı detay hatası: {str(e)}", user_id=user_id)
        flash('Kullanıcı detayları yüklenirken hata oluştu!', 'error')
        return redirect(url_for('users.users'))

@users_bp.route('/api/users')
def api_users():
    """Kullanıcı listesi API"""
    try:
        config = Config()
        user_manager = UserManager(config)
        
        # Parametreleri al
        status_filter = request.args.get('status', 'all')
        risk_filter = request.args.get('risk', 'all')
        search_query = request.args.get('search')
        sort_by = request.args.get('sort_by', 'last_activity')
        sort_order = request.args.get('sort_order', 'desc')
        limit = int(request.args.get('limit', 50))
        
        # Kullanıcı listesini getir
        user_data = user_manager.get_user_list(
            status_filter=status_filter,
            risk_filter=risk_filter,
            search_query=search_query,
            sort_by=sort_by,
            sort_order=sort_order,
            limit=limit
        )
        
        return jsonify({
            'success': True,
            'data': user_data,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@users_bp.route('/api/users/<int:user_id>')
def api_user_detail(user_id):
    """Kullanıcı detay API"""
    try:
        config = Config()
        user_manager = UserManager(config)
        
        user_details = user_manager.get_user_details(user_id)
        
        return jsonify({
            'success': True,
            'data': user_details,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@users_bp.route('/api/users/<int:user_id>/verify', methods=['POST'])
def api_manual_verify_user(user_id):
    """Manuel doğrulama API"""
    try:
        if session.get('user_role') not in ['admin', 'moderator']:
            return jsonify({'success': False, 'error': 'Yetki yok'}), 403
        
        config = Config()
        database = Database()
        logger = Logger()
        
        # Kullanıcı bilgilerini al
        request_data = request.get_json() or {}
        username = request_data.get('username', f'User_{user_id}')
        reason = request_data.get('reason', 'Manuel doğrulama')
        
        # Doğrulama yap
        success = database.add_verified_user(
            user_id, username, manual=True, 
            admin_id=0, confidence=100
        )
        
        if success:
            admin_user = session.get('username', 'Unknown')
            
            # Admin aksiyonu kaydet
            database.log_admin_action(
                0, admin_user, 'manuel_dogrulama', 
                user_id, username, {'reason': reason}
            )
            
            logger.admin_action(
                0, admin_user, 'manuel_dogrulama', username,
                {'user_id': user_id, 'reason': reason}
            )
            
            return jsonify({
                'success': True,
                'message': f'{username} başarıyla doğrulandı',
                'admin': admin_user
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Doğrulama işlemi başarısız'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@users_bp.route('/api/users/<int:user_id>/unverify', methods=['POST'])
def api_unverify_user(user_id):
    """Doğrulamayı kaldırma API"""
    try:
        if session.get('user_role') != 'admin':  # Sadece admin
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        database = Database()
        logger = Logger()
        
        # Kullanıcı bilgisini al
        user_data = database.get_verified_user_data(user_id)
        if not user_data:
            return jsonify({'success': False, 'error': 'Kullanıcı doğrulanmamış'})
        
        username = user_data.get('username', f'User_{user_id}')
        reason = request.get_json().get('reason', 'Admin kararı') if request.is_json else 'Admin kararı'
        
        # Doğrulamayı kaldır
        success = database.remove_verified_user(user_id)
        
        if success:
            admin_user = session.get('username', 'Unknown')
            
            # Admin aksiyonu kaydet
            database.log_admin_action(
                0, admin_user, 'dogrulama_kaldir',
                user_id, username, {'reason': reason}
            )
            
            logger.admin_action(
                0, admin_user, 'dogrulama_kaldir', username,
                {'user_id': user_id, 'reason': reason}
            )
            
            return jsonify({
                'success': True,
                'message': f'{username} doğrulaması kaldırıldı',
                'admin': admin_user
            })
        else:
            return jsonify({
                'success': False,
                'error': 'İşlem başarısız'
            })
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@users_bp.route('/api/users/<int:user_id>/blacklist', methods=['POST'])
def api_blacklist_user(user_id):
    """Kullanıcıyı blacklist'e alma API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        security = SecurityManager(config)
        logger = Logger()
        
        reason = request.get_json().get('reason', 'Admin kararı') if request.is_json else 'Admin kararı'
        
        # Blacklist'e ekle
        security.add_to_blacklist('user_ids', str(user_id), reason)
        
        admin_user = session.get('username', 'Unknown')
        
        # Admin aksiyonu kaydet
        logger.admin_action(
            0, admin_user, 'kullanici_blacklist',
            f'User_{user_id}', {'user_id': user_id, 'reason': reason}
        )
        
        return jsonify({
            'success': True,
            'message': f'Kullanıcı blacklist\'e eklendi',
            'admin': admin_user
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@users_bp.route('/api/users/<int:user_id>/whitelist', methods=['POST'])
def api_whitelist_user(user_id):
    """Kullanıcıyı whitelist'e alma API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        security = SecurityManager(config)
        logger = Logger()
        
        # Blacklist'ten kaldır
        security.remove_from_blacklist('user_ids', str(user_id))
        
        # Suspicious listesinden de temizle
        suspicious_users = security.load_json(security.suspicious_users_file, {})
        if str(user_id) in suspicious_users:
            del suspicious_users[str(user_id)]
            security.save_json(security.suspicious_users_file, suspicious_users)
        
        admin_user = session.get('username', 'Unknown')
        
        # Admin aksiyonu kaydet
        logger.admin_action(
            0, admin_user, 'kullanici_whitelist',
            f'User_{user_id}', {'user_id': user_id}
        )
        
        return jsonify({
            'success': True,
            'message': 'Kullanıcı whitelist\'e eklendi',
            'admin': admin_user
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@users_bp.route('/api/users/bulk-action', methods=['POST'])
def api_bulk_user_action():
    """Toplu kullanıcı işlemi API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        request_data = request.get_json()
        action = request_data.get('action')
        user_ids = request_data.get('user_ids', [])
        reason = request_data.get('reason', 'Toplu işlem')
        
        if not action or not user_ids:
            return jsonify({'success': False, 'error': 'Geçersiz parametreler'})
        
        config = Config()
        database = Database()
        security = SecurityManager(config)
        logger = Logger()
        
        admin_user = session.get('username', 'Unknown')
        results = []
        
        for user_id in user_ids:
            try:
                user_id = int(user_id)
                
                if action == 'verify':
                    success = database.add_verified_user(
                        user_id, f'User_{user_id}', manual=True,
                        admin_id=0, confidence=100
                    )
                    results.append({'user_id': user_id, 'success': success, 'action': 'verified'})
                
                elif action == 'unverify':
                    success = database.remove_verified_user(user_id)
                    results.append({'user_id': user_id, 'success': success, 'action': 'unverified'})
                
                elif action == 'blacklist':
                    security.add_to_blacklist('user_ids', str(user_id), reason)
                    results.append({'user_id': user_id, 'success': True, 'action': 'blacklisted'})
                
                elif action == 'whitelist':
                    security.remove_from_blacklist('user_ids', str(user_id))
                    results.append({'user_id': user_id, 'success': True, 'action': 'whitelisted'})
                
                else:
                    results.append({'user_id': user_id, 'success': False, 'error': 'Geçersiz işlem'})
                
            except Exception as e:
                results.append({'user_id': user_id, 'success': False, 'error': str(e)})
        
        # Toplu admin aksiyonu kaydet
        logger.admin_action(
            0, admin_user, f'toplu_{action}',
            f'{len(user_ids)} kullanıcı', {
                'action': action,
                'user_count': len(user_ids),
                'reason': reason,
                'results': results
            }
        )
        
        successful = len([r for r in results if r['success']])
        
        return jsonify({
            'success': True,
            'message': f'{successful}/{len(user_ids)} kullanıcı için işlem başarılı',
            'results': results,
            'admin': admin_user
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@users_bp.route('/api/users/export')
def api_export_users():
    """Kullanıcı listesi dışa aktarma API"""
    try:
        if session.get('user_role') != 'admin':
            return jsonify({'success': False, 'error': 'Admin yetkisi gerekli'}), 403
        
        config = Config()
        user_manager = UserManager(config)
        
        # Tüm kullanıcıları al
        user_data = user_manager.get_user_list(limit=10000)
        
        # Export formatı hazırla
        export_data = {
            'exported_at': datetime.now().isoformat(),
            'exported_by': session.get('username'),
            'total_users': user_data['total_count'],
            'users': user_data['users'],
            'statistics': user_data['stats']
        }
        
        return jsonify({
            'success': True,
            'data': export_data,
            'download_filename': f"users_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })