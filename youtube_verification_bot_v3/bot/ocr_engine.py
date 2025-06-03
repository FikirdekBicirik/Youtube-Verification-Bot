# bot/ocr_engine.py
import pytesseract
from PIL import Image, ImageEnhance, ImageFilter, ImageOps
import cv2
import numpy as np
import re
from typing import Dict, List, Optional, Tuple
import io
import requests
from datetime import datetime
import os
import tempfile

from utils.logger import Logger
from utils.config import Config

class OCREngine:
    """Gelişmiş OCR (Optical Character Recognition) sistemi"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger()
        
        # OCR ayarları
        self.language = config.get('OCR_LANGUAGE', 'tur+eng')
        self.confidence_threshold = config.get('OCR_CONFIDENCE_THRESHOLD', 60)
        self.debug_mode = config.get('OCR_DEBUG', False)
        
        # Tesseract konfigürasyonu
        self.tesseract_config = {
            'basic': '--oem 3 --psm 6',
            'single_block': '--oem 3 --psm 7',
            'single_line': '--oem 3 --psm 8',
            'single_word': '--oem 3 --psm 10',
            'sparse_text': '--oem 3 --psm 11',
            'raw_line': '--oem 3 --psm 13'
        }
        
        # YouTube özel metinleri
        self.youtube_patterns = {
            'subscribe_button': [
                r'abone\s+ol(?:undu)?',
                r'subscrib(?:e|ed)',
                r'follow',
                r'takip\s+et'
            ],
            'like_button': [
                r'beğen(?:din)?',
                r'lik(?:e|ed)',
                r'thumbs?\s+up'
            ],
            'comment_section': [
                r'yorum(?:lar)?',
                r'comment(?:s)?',
                r'yanıtla',
                r'reply',
                r'cevapla'
            ],
            'channel_name': [
                r'@[\w\s]+',
                r'[\w\s]+\s*•\s*\d+[KMB]?\s*(?:subscriber|abone)',
                r'[\w\s]+\s+kanal[ıi]'
            ],
            'view_count': [
                r'\d+(?:[.,]\d+)*\s*(?:views?|izlenme|görüntülenme)',
                r'\d+[KMB]\s*(?:views?|izlenme)'
            ],
            'publish_date': [
                r'\d+\s*(?:gün|day|saat|hour|dakika|minute|saniye|second)\s*önce',
                r'\d+\s*(?:ago|before)',
                r'yayınlandı|published|uploaded'
            ]
        }
        
        # Metin temizleme filtreleri
        self.text_filters = [
            (r'\s+', ' '),  # Çoklu boşlukları tek boşluğa çevir
            (r'[^\w\s@•.,!?()-]', ''),  # Özel karakterleri temizle
            (r'(?i)(?:cookie|gdpr|privacy)', ''),  # GDPR/Cookie metinlerini kaldır
            (r'(?i)(?:ad|advertisement|reklam)', ''),  # Reklam metinlerini kaldır
        ]
        
        self.test_ocr_setup()
    
    def test_ocr_setup(self):
        """OCR kurulumunu test et"""
        try:
            # Basit test resmi oluştur
            test_image = Image.new('RGB', (200, 50), color='white')
            # Test metni eklemek için PIL kullanabiliriz ama basit test yeterli
            
            # Tesseract çağrısı test et
            result = pytesseract.image_to_string(test_image, lang='eng', config='--psm 6')
            
            self.logger.info("OCR sistemi başarıyla başlatıldı")
            
        except Exception as e:
            self.logger.error(f"OCR kurulum hatası: {str(e)}")
            self.logger.warning("OCR çalışmayabilir! Tesseract kurulumunu kontrol edin.")
    
    async def extract_text_advanced(self, image: Image.Image) -> str:
        """Gelişmiş metin çıkarma"""
        try:
            self.logger.debug("Gelişmiş OCR analizi başlatılıyor")
            
            # Farklı ön işleme yöntemleri ile metin çıkar
            extraction_methods = [
                self.extract_with_basic_preprocessing,
                self.extract_with_contrast_enhancement,
                self.extract_with_edge_detection,
                self.extract_with_noise_removal,
                self.extract_with_binary_threshold,
                self.extract_with_morphological_operations
            ]
            
            all_results = []
            
            for method in extraction_methods:
                try:
                    result = await method(image)
                    if result and len(result.strip()) > 10:  # Minimum metin uzunluğu
                        all_results.append(result)
                        
                        if self.debug_mode:
                            self.logger.debug(f"OCR yöntemi başarılı: {method.__name__}")
                            
                except Exception as e:
                    if self.debug_mode:
                        self.logger.debug(f"OCR yöntemi başarısız {method.__name__}: {str(e)}")
                    continue
            
            # En iyi sonucu seç
            best_result = self.select_best_ocr_result(all_results)
            
            if best_result:
                # Metni temizle ve normalize et
                cleaned_text = self.clean_and_normalize_text(best_result)
                
                self.logger.info(f"OCR başarılı - {len(cleaned_text)} karakter çıkarıldı")
                
                if self.debug_mode:
                    self.save_debug_info(image, cleaned_text, all_results)
                
                return cleaned_text
            else:
                self.logger.warning("OCR hiçbir yöntemle başarılı olamadı")
                return ""
                
        except Exception as e:
            self.logger.error(f"Gelişmiş OCR hatası: {str(e)}")
            return ""
    
    async def extract_with_basic_preprocessing(self, image: Image.Image) -> str:
        """Temel ön işleme ile OCR"""
        try:
            # Resmi büyüt
            scale_factor = 2
            width, height = image.size
            resized = image.resize((width * scale_factor, height * scale_factor), Image.LANCZOS)
            
            # Kontrastı artır
            enhancer = ImageEnhance.Contrast(resized)
            contrasted = enhancer.enhance(1.5)
            
            # Keskinliği artır
            enhancer = ImageEnhance.Sharpness(contrasted)
            sharpened = enhancer.enhance(1.2)
            
            # OCR uygula
            text = pytesseract.image_to_string(
                sharpened, 
                lang=self.language,
                config=self.tesseract_config['basic']
            )
            
            return text.strip()
            
        except Exception as e:
            raise Exception(f"Temel ön işleme hatası: {str(e)}")
    
    async def extract_with_contrast_enhancement(self, image: Image.Image) -> str:
        """Kontrast artırma ile OCR"""
        try:
            # Histogram eşitleme
            image_array = np.array(image)
            
            # Her kanal için histogram eşitleme
            enhanced_channels = []
            for i in range(3):  # RGB kanalları
                channel = image_array[:, :, i]
                enhanced_channel = cv2.equalizeHist(channel)
                enhanced_channels.append(enhanced_channel)
            
            enhanced_array = np.stack(enhanced_channels, axis=2)
            enhanced_image = Image.fromarray(enhanced_array)
            
            # Ek kontrast artırma
            enhancer = ImageEnhance.Contrast(enhanced_image)
            final_image = enhancer.enhance(2.0)
            
            text = pytesseract.image_to_string(
                final_image,
                lang=self.language,
                config=self.tesseract_config['basic']
            )
            
            return text.strip()
            
        except Exception as e:
            raise Exception(f"Kontrast artırma hatası: {str(e)}")
    
    async def extract_with_edge_detection(self, image: Image.Image) -> str:
        """Kenar tespit ile OCR"""
        try:
            # OpenCV formatına çevir
            cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
            
            # Gaussian blur uygula
            blurred = cv2.GaussianBlur(gray, (5, 5), 0)
            
            # Canny edge detection
            edges = cv2.Canny(blurred, 50, 150)
            
            # Kenarları kalınlaştır
            kernel = np.ones((2, 2), np.uint8)
            dilated = cv2.dilate(edges, kernel, iterations=1)
            
            # PIL formatına geri çevir
            edge_image = Image.fromarray(dilated)
            
            text = pytesseract.image_to_string(
                edge_image,
                lang=self.language,
                config=self.tesseract_config['sparse_text']
            )
            
            return text.strip()
            
        except Exception as e:
            raise Exception(f"Kenar tespit hatası: {str(e)}")
    
    async def extract_with_noise_removal(self, image: Image.Image) -> str:
        """Gürültü temizleme ile OCR"""
        try:
            # OpenCV formatına çevir
            cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
            
            # Median filter ile gürültü temizle
            denoised = cv2.medianBlur(gray, 3)
            
            # Bilateral filter uygula
            bilateral = cv2.bilateralFilter(denoised, 9, 75, 75)
            
            # PIL formatına çevir
            clean_image = Image.fromarray(bilateral)
            
            # Kontrast artır
            enhancer = ImageEnhance.Contrast(clean_image)
            final_image = enhancer.enhance(1.8)
            
            text = pytesseract.image_to_string(
                final_image,
                lang=self.language,
                config=self.tesseract_config['basic']
            )
            
            return text.strip()
            
        except Exception as e:
            raise Exception(f"Gürültü temizleme hatası: {str(e)}")
    
    async def extract_with_binary_threshold(self, image: Image.Image) -> str:
        """İkili eşikleme ile OCR"""
        try:
            # Gri tonlamaya çevir
            gray_image = image.convert('L')
            
            # Otsu threshold
            cv_gray = np.array(gray_image)
            _, binary = cv2.threshold(cv_gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            
            # Adaptif threshold
            adaptive = cv2.adaptiveThreshold(
                cv_gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
            )
            
            # İki sonucu birleştir
            combined = cv2.bitwise_and(binary, adaptive)
            
            # PIL formatına çevir
            binary_image = Image.fromarray(combined)
            
            text = pytesseract.image_to_string(
                binary_image,
                lang=self.language,
                config=self.tesseract_config['basic']
            )
            
            return text.strip()
            
        except Exception as e:
            raise Exception(f"İkili eşikleme hatası: {str(e)}")
    
    async def extract_with_morphological_operations(self, image: Image.Image) -> str:
        """Morfolojik işlemler ile OCR"""
        try:
            # Gri tonlamaya çevir
            cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
            
            # Binary threshold
            _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            
            # Morfolojik operasyonlar
            # Closing: small holes içinde fill
            kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
            closed = cv2.morphologyEx(binary, cv2.MORPH_CLOSE, kernel)
            
            # Opening: noise removal
            opened = cv2.morphologyEx(closed, cv2.MORPH_OPEN, kernel)
            
            # PIL formatına çevir
            processed_image = Image.fromarray(opened)
            
            text = pytesseract.image_to_string(
                processed_image,
                lang=self.language,
                config=self.tesseract_config['basic']
            )
            
            return text.strip()
            
        except Exception as e:
            raise Exception(f"Morfolojik işlem hatası: {str(e)}")
    
    def select_best_ocr_result(self, results: List[str]) -> str:
        """En iyi OCR sonucunu seç"""
        if not results:
            return ""
        
        if len(results) == 1:
            return results[0]
        
        # Scoring system
        scored_results = []
        
        for result in results:
            score = 0
            
            # Uzunluk skoru (çok kısa veya çok uzun metinler düşük skor)
            length = len(result.strip())
            if 50 <= length <= 2000:
                score += 20
            elif 20 <= length <= 3000:
                score += 10
            
            # YouTube keyword skoru
            result_lower = result.lower()
            youtube_keywords = [
                'youtube', 'subscribe', 'abone', 'like', 'beğen', 
                'comment', 'yorum', 'share', 'paylaş', 'view', 'izlenme'
            ]
            
            for keyword in youtube_keywords:
                if keyword in result_lower:
                    score += 5
            
            # Kanal adı skoru
            expected_channel = self.config.get('YOUR_CHANNEL_NAME', '').lower()
            if expected_channel and expected_channel in result_lower:
                score += 30
            
            # Sayı/rakam dengesi (çok fazla rakam spam olabilir)
            digit_ratio = len(re.findall(r'\d', result)) / len(result) if result else 0
            if 0.1 <= digit_ratio <= 0.3:  # Optimal rakam oranı
                score += 10
            elif digit_ratio > 0.5:  # Çok fazla rakam
                score -= 20
            
            # Türkçe/İngilizce karakter dengesi
            turkish_chars = len(re.findall(r'[çğıöşüÇĞIİÖŞÜ]', result))
            if turkish_chars > 0:
                score += 5  # Türkçe karakterler YouTube Türkiye için pozitif
            
            # Özel karakter oranı (çok fazla özel karakter = gürültü)
            special_char_ratio = len(re.findall(r'[^\w\s]', result)) / len(result) if result else 0
            if special_char_ratio < 0.2:
                score += 10
            elif special_char_ratio > 0.4:
                score -= 15
            
            scored_results.append((result, score))
        
        # En yüksek skora sahip sonucu seç
        best_result = max(scored_results, key=lambda x: x[1])
        
        if self.debug_mode:
            self.logger.debug(f"OCR sonuç skorları: {[(len(r), s) for r, s in scored_results]}")
            self.logger.debug(f"En iyi sonuç skoru: {best_result[1]}")
        
        return best_result[0]
    
    def clean_and_normalize_text(self, text: str) -> str:
        """Metni temizle ve normalize et"""
        if not text:
            return ""
        
        # Temel temizlik
        cleaned = text.strip()
        
        # Filtreleri uygula
        for pattern, replacement in self.text_filters:
            cleaned = re.sub(pattern, replacement, cleaned)
        
        # Satır sonlarını normalize et
        cleaned = re.sub(r'\n+', '\n', cleaned)
        cleaned = re.sub(r'\r', '', cleaned)
        
        # Gereksiz boşlukları temizle
        lines = []
        for line in cleaned.split('\n'):
            line = line.strip()
            if len(line) > 2:  # Çok kısa satırları filtrele
                lines.append(line)
        
        # Unicode normalize
        import unicodedata
        normalized = unicodedata.normalize('NFKC', '\n'.join(lines))
        
        return normalized
    
    def extract_youtube_elements(self, text: str) -> Dict[str, List[str]]:
        """YouTube özel elementlerini çıkar"""
        elements = {}
        text_lower = text.lower()
        
        for element_type, patterns in self.youtube_patterns.items():
            found_elements = []
            
            for pattern in patterns:
                matches = re.findall(pattern, text_lower, re.IGNORECASE | re.MULTILINE)
                found_elements.extend(matches)
            
            # Duplikatları kaldır ve temizle
            unique_elements = list(set(found_elements))
            cleaned_elements = [elem.strip() for elem in unique_elements if elem.strip()]
            
            elements[element_type] = cleaned_elements
        
        return elements
    
    def detect_language_distribution(self, text: str) -> Dict[str, float]:
        """Metindeki dil dağılımını tespit et"""
        if not text:
            return {}
        
        total_chars = len(text)
        
        # Türkçe karakterler
        turkish_chars = len(re.findall(r'[çğıöşüÇĞIİÖŞÜ]', text))
        
        # İngilizce kelimeler (basit tespit)
        english_words = len(re.findall(r'\b(?:the|and|or|but|in|on|at|to|for|of|with|by)\b', text.lower()))
        
        # Türkçe kelimeler (basit tespit)
        turkish_words = len(re.findall(r'\b(?:ve|veya|ama|ile|için|den|dan|da|de|bir|bu|şu)\b', text.lower()))
        
        # Rakamlar
        digits = len(re.findall(r'\d', text))
        
        distribution = {
            'turkish_char_ratio': turkish_chars / total_chars if total_chars > 0 else 0,
            'english_word_count': english_words,
            'turkish_word_count': turkish_words,
            'digit_ratio': digits / total_chars if total_chars > 0 else 0,
            'estimated_language': 'turkish' if turkish_chars > 0 or turkish_words > english_words else 'english'
        }
        
        return distribution
    
    def extract_specific_data(self, text: str) -> Dict[str, any]:
        """Spesifik veri türlerini çıkar"""
        data = {
            'channel_names': [],
            'subscriber_counts': [],
            'view_counts': [],
            'like_counts': [],
            'comment_counts': [],
            'timestamps': [],
            'video_titles': []
        }
        
        text_lower = text.lower()
        
        # Kanal isimleri
        channel_patterns = [
            r'@(\w+)',
            r'(\w+(?:\s+\w+)*)\s*•\s*\d+[KMB]?\s*(?:subscriber|abone)',
            r'(\w+(?:\s+\w+)*)\s+kanal[ıi]'
        ]
        
        for pattern in channel_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            data['channel_names'].extend([match.strip() for match in matches if isinstance(match, str)])
        
        # Abone sayıları
        subscriber_patterns = [
            r'(\d+(?:[.,]\d+)*[KMB]?)\s*(?:subscriber|abone)',
            r'(\d+(?:[.,]\d+)*)\s*(?:subscriber|abone)'
        ]
        
        for pattern in subscriber_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            data['subscriber_counts'].extend(matches)
        
        # İzlenme sayıları
        view_patterns = [
            r'(\d+(?:[.,]\d+)*[KMB]?)\s*(?:view|izlenme|görüntülenme)',
            r'(\d+(?:[.,]\d+)*)\s*kez\s*izlendi'
        ]
        
        for pattern in view_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            data['view_counts'].extend(matches)
        
        # Beğeni sayıları
        like_patterns = [
            r'(\d+(?:[.,]\d+)*[KMB]?)\s*(?:like|beğeni)',
            r'(\d+(?:[.,]\d+)*)\s*kişi\s*beğendi'
        ]
        
        for pattern in like_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            data['like_counts'].extend(matches)
        
        # Yorum sayıları
        comment_patterns = [
            r'(\d+(?:[.,]\d+)*[KMB]?)\s*(?:comment|yorum)',
            r'(\d+(?:[.,]\d+)*)\s*yorum'
        ]
        
        for pattern in comment_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            data['comment_counts'].extend(matches)
        
        # Zaman damgaları
        time_patterns = [
            r'(\d+)\s*(?:gün|day|saat|hour|dakika|minute|saniye|second)\s*önce',
            r'(\d+)\s*(?:ago|before)',
            r'(\d{1,2}:\d{2}(?::\d{2})?)',  # Video süresi
        ]
        
        for pattern in time_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            data['timestamps'].extend(matches)
        
        return data
    
    def save_debug_info(self, image: Image.Image, extracted_text: str, all_results: List[str]):
        """Debug bilgilerini kaydet"""
        if not self.debug_mode:
            return
        
        try:
            # Debug klasörü oluştur
            debug_dir = "data/debug/ocr"
            os.makedirs(debug_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Resmi kaydet
            image_path = os.path.join(debug_dir, f"ocr_input_{timestamp}.png")
            image.save(image_path)
            
            # OCR sonuçlarını kaydet
            results_path = os.path.join(debug_dir, f"ocr_results_{timestamp}.txt")
            with open(results_path, 'w', encoding='utf-8') as f:
                f.write("=== SELECTED RESULT ===\n")
                f.write(extracted_text)
                f.write("\n\n=== ALL RESULTS ===\n")
                for i, result in enumerate(all_results):
                    f.write(f"\n--- Result {i+1} ---\n")
                    f.write(result)
                    f.write(f"\n--- Length: {len(result)} ---\n")
            
            # YouTube elementlerini kaydet
            elements = self.extract_youtube_elements(extracted_text)
            elements_path = os.path.join(debug_dir, f"youtube_elements_{timestamp}.json")
            import json
            with open(elements_path, 'w', encoding='utf-8') as f:
                json.dump(elements, f, indent=2, ensure_ascii=False)
            
            self.logger.debug(f"OCR debug bilgileri kaydedildi: {debug_dir}")
            
        except Exception as e:
            self.logger.error(f"Debug bilgi kaydetme hatası: {str(e)}")
    
    async def test_connection(self) -> bool:
        """OCR bağlantı testi"""
        try:
            # Test resmi oluştur
            test_image = Image.new('RGB', (300, 100), color='white')
            
            # Basit OCR testi
            result = pytesseract.image_to_string(test_image, lang='eng')
            
            # Dil testi
            if self.language != 'eng':
                result = pytesseract.image_to_string(test_image, lang=self.language)
            
            return True
            
        except Exception as e:
            self.logger.error(f"OCR bağlantı testi başarısız: {str(e)}")
            return False
    
    def get_ocr_info(self) -> Dict[str, any]:
        """OCR motor bilgilerini getir"""
        try:
            info = {
                'tesseract_version': pytesseract.get_tesseract_version(),
                'language': self.language,
                'confidence_threshold': self.confidence_threshold,
                'debug_mode': self.debug_mode,
                'available_languages': [],
                'config_modes': list(self.tesseract_config.keys()),
                'status': 'active'
            }
            
            # Mevcut dilleri tespit et (eğer mümkünse)
            try:
                info['available_languages'] = pytesseract.get_languages()
            except:
                info['available_languages'] = ['eng', 'tur']  # Default
            
            return info
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'tesseract_version': 'unknown'
            }
    
    def analyze_text_quality(self, text: str) -> Dict[str, any]:
        """Çıkarılan metnin kalitesini analiz et"""
        if not text:
            return {
                'quality_score': 0,
                'issues': ['No text extracted'],
                'recommendations': ['Check image quality', 'Verify text is visible']
            }
        
        issues = []
        recommendations = []
        score = 100
        
        # Uzunluk kontrolü
        if len(text) < 20:
            issues.append('Text too short')
            recommendations.append('Ensure image contains readable text')
            score -= 30
        elif len(text) > 5000:
            issues.append('Text too long (possible OCR noise)')
            recommendations.append('Check for image artifacts')
            score -= 10
        
        # Karakter kalitesi
        special_char_ratio = len(re.findall(r'[^\w\s]', text)) / len(text)
        if special_char_ratio > 0.3:
            issues.append('High special character ratio')
            recommendations.append('Improve image preprocessing')
            score -= 20
        
        # Rakam dengesi
        digit_ratio = len(re.findall(r'\d', text)) / len(text)
        if digit_ratio > 0.7:
            issues.append('Too many digits (possible noise)')
            recommendations.append('Check OCR accuracy')
            score -= 25
        
        # YouTube relevanslığı
        youtube_keywords = ['youtube', 'subscribe', 'abone', 'like', 'beğen', 'comment', 'yorum']
        found_keywords = [kw for kw in youtube_keywords if kw in text.lower()]
        
        if not found_keywords:
            issues.append('No YouTube-related content detected')
            recommendations.append('Verify this is a YouTube screenshot')
            score -= 40
        else:
            score += len(found_keywords) * 5  # Bonus for relevant content
        
        # Dil tutarlılığı
        lang_dist = self.detect_language_distribution(text)
        if lang_dist['estimated_language'] != 'turkish' and lang_dist['estimated_language'] != 'english':
            issues.append('Unclear language detection')
            recommendations.append('Check text clarity')
            score -= 15
        
        quality_score = max(0, min(100, score))
        
        return {
            'quality_score': quality_score,
            'issues': issues,
            'recommendations': recommendations,
            'character_count': len(text),
            'word_count': len(text.split()),
            'language_distribution': lang_dist,
            'youtube_keywords_found': found_keywords,
            'special_char_ratio': round(special_char_ratio, 3),
            'digit_ratio': round(digit_ratio, 3)
        }