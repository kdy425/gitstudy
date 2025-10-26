import re
import sys
from pathlib import Path

class SensitiveDataScanner:
    def __init__(self, input_file):
        self.input_file = input_file
        self.findings = {
            'passwords': [],
            'tokens': [],
            'api_keys': [],
            'emails': [],
            'phones': [],
            'credit_cards': [],
            'session_ids': [],
            'urls': [],
            'ips': [],
            'custom': []
        }
        
        # 탐지 패턴 정의
        self.patterns = {
            'password': [
                r'password["\s:=]+([^\s"\']+)',
                r'passwd["\s:=]+([^\s"\']+)',
                r'pwd["\s:=]+([^\s"\']+)',
                r'"password"\s*:\s*"([^"]+)"',
                r'<password>([^<]+)</password>'
            ],
            'token': [
                r'token["\s:=]+([A-Za-z0-9_\-\.]{20,})',
                r'bearer\s+([A-Za-z0-9_\-\.]{20,})',
                r'authorization["\s:=]+([A-Za-z0-9_\-\.]{20,})',
                r'"token"\s*:\s*"([^"]+)"',
                r'jwt["\s:=]+([A-Za-z0-9_\-\.]+)'
            ],
            'api_key': [
                r'api[_-]?key["\s:=]+([A-Za-z0-9_\-]{20,})',
                r'apikey["\s:=]+([A-Za-z0-9_\-]{20,})',
                r'access[_-]?key["\s:=]+([A-Za-z0-9_\-]{20,})',
                r'secret[_-]?key["\s:=]+([A-Za-z0-9_\-]{20,})',
                r'sk_live_[A-Za-z0-9]{24,}',
                r'pk_live_[A-Za-z0-9]{24,}'
            ],
            'email': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            ],
            'phone': [
                r'01[0-9]-?\d{3,4}-?\d{4}',  # 한국 휴대폰
                r'\+82-?10-?\d{3,4}-?\d{4}',
                r'\d{3}-\d{4}-\d{4}'  # 일반 전화번호
            ],
            'credit_card': [
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                r'\b\d{13,19}\b'  # 카드번호 (공백/하이픈 없음)
            ],
            'session': [
                r'session["\s:=]+([A-Za-z0-9_\-]{20,})',
                r'sessionid["\s:=]+([A-Za-z0-9_\-]{20,})',
                r'jsessionid["\s:=]+([A-Za-z0-9_\-]{20,})',
                r'phpsessid["\s:=]+([A-Za-z0-9_\-]{20,})'
            ],
            'url': [
                r'https?://[^\s<>"\']+',
                r'ftp://[^\s<>"\']+',
                r'file://[^\s<>"\']+'
            ],
            'ip': [
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ]
        }
    
    def scan(self):
        """파일을 스캔하여 민감 정보 탐지"""
        try:
            with open(self.input_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            print(f"[+] 스캔 시작: {self.input_file}")
            print(f"[+] 총 {len(lines):,}줄 분석 중...\n")
            
            # 각 패턴별로 검색
            for category, pattern_list in self.patterns.items():
                for pattern in pattern_list:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        try:
                            value = match.group(1) if match.groups() else match.group(0)
                            self._add_finding(category, value, pattern)
                        except:
                            value = match.group(0)
                            self._add_finding(category, value, pattern)
            
            return self.findings
            
        except FileNotFoundError:
            print(f"[!] 파일을 찾을 수 없습니다: {self.input_file}")
            sys.exit(1)
        except Exception as e:
            print(f"[!] 오류 발생: {e}")
            sys.exit(1)
    
    def _add_finding(self, category, value, pattern):
        """발견 항목 추가 (중복 제거)"""
        # 너무 짧거나 일반적인 값 필터링
        if len(value) < 3:
            return
        
        # 카테고리별 매핑
        category_map = {
            'password': 'passwords',
            'token': 'tokens',
            'api_key': 'api_keys',
            'email': 'emails',
            'phone': 'phones',
            'credit_card': 'credit_cards',
            'session': 'session_ids',
            'url': 'urls',
            'ip': 'ips'
        }
        
        key = category_map.get(category, 'custom')
        
        # 중복 체크
        if value not in self.findings[key]:
            self.findings[key].append(value)
    
    def print_results(self):
        """결과 출력"""
        print("=" * 80)
        print("민감 정보 탐지 결과")
        print("=" * 80)
        
        total_count = 0
        
        categories = {
            'passwords': '🔐 패스워드',
            'tokens': '🎫 토큰/인증',
            'api_keys': '🔑 API 키',
            'emails': '📧 이메일',
            'phones': '📱 전화번호',
            'credit_cards': '💳 신용카드',
            'session_ids': '🍪 세션 ID',
            'urls': '🔗 URL',
            'ips': '🌐 IP 주소'
        }
        
        for key, title in categories.items():
            items = self.findings[key]
            if items:
                print(f"\n{title} ({len(items)}개 발견)")
                print("-" * 80)
                for idx, item in enumerate(items[:20], 1):  # 최대 20개만 출력
                    # 민감 정보는 일부만 표시
                    if key in ['passwords', 'tokens', 'api_keys', 'credit_cards', 'session_ids']:
                        masked = self._mask_value(item)
                        print(f"  [{idx}] {masked}")
                    else:
                        print(f"  [{idx}] {item}")
                
                if len(items) > 20:
                    print(f"  ... 외 {len(items) - 20}개 더 발견됨")
                
                total_count += len(items)
        
        print("\n" + "=" * 80)
        print(f"총 {total_count}개의 민감 정보가 발견되었습니다.")
        print("=" * 80)
    
    def _mask_value(self, value):
        """민감 정보 마스킹"""
        if len(value) <= 8:
            return value[:2] + "*" * (len(value) - 2)
        else:
            return value[:4] + "*" * (len(value) - 8) + value[-4:]
    
    def save_results(self, output_file):
        """결과를 파일로 저장"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("민감 정보 탐지 결과\n")
                f.write(f"입력 파일: {self.input_file}\n")
                f.write("=" * 80 + "\n\n")
                
                categories = {
                    'passwords': '패스워드',
                    'tokens': '토큰/인증',
                    'api_keys': 'API 키',
                    'emails': '이메일',
                    'phones': '전화번호',
                    'credit_cards': '신용카드',
                    'session_ids': '세션 ID',
                    'urls': 'URL',
                    'ips': 'IP 주소'
                }
                
                for key, title in categories.items():
                    items = self.findings[key]
                    if items:
                        f.write(f"\n[{title}] ({len(items)}개)\n")
                        f.write("-" * 80 + "\n")
                        for item in items:
                            f.write(f"{item}\n")
            
            print(f"\n[+] 결과가 저장되었습니다: {output_file}")
            
        except Exception as e:
            print(f"[!] 파일 저장 실패: {e}")


def main():
    """메인 함수"""
    if len(sys.argv) < 2:
        print("사용법: python sensitive_scanner.py <strings.txt 경로> [출력파일.txt]")
        print("\n예시:")
        print("  python sensitive_scanner.py dump/strings.txt")
        print("  python sensitive_scanner.py dump/strings.txt result.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    # 스캔 실행
    scanner = SensitiveDataScanner(input_file)
    scanner.scan()
    
    # 결과 출력
    scanner.print_results()
    
    # 결과 저장 (선택사항)
    if output_file:
        scanner.save_results(output_file)


if __name__ == "__main__":
    main()
