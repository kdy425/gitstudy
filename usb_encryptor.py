import os
import sys
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class USBEncryptor:
    def __init__(self, password):
        # AES-128은 16바이트 키 필요
        self.key = hashlib.sha256(password.encode()).digest()[:16]
        # 속도 최적화: 파일당 앞 1MB만 암호화
        self.chunk_size = 1024 * 1024  # 1MB
        # self.chunk_size = 512 * 1024  # 512KB만 암호화 (더 빠름)
        # self.chunk_size = 5 * 1024 * 1024  # 5MB 암호화 (더 안전)
        self.marker = b'ENC_MARKER_V1'
    
    def encrypt_file(self, file_path):
        """파일 앞부분만 암호화 (속도 최적화)"""
        try:
            # 이미 암호화된 파일인지 확인
            with open(file_path, 'rb') as f:
                marker_check = f.read(len(self.marker))
                if marker_check == self.marker:
                    print(f"[!] 이미 암호화됨: {file_path}")
                    return False
            
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            file_size = len(file_data)
            
            # 암호화할 크기 결정 (최대 chunk_size)
            encrypt_size = min(file_size, self.chunk_size)
            
            # 암호화할 부분과 그대로 둘 부분 분리
            data_to_encrypt = file_data[:encrypt_size]
            remaining_data = file_data[encrypt_size:]
            
            # AES-128 CBC 모드 암호화
            iv = get_random_bytes(16)
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            
            # 패딩 후 암호화
            encrypted_data = cipher.encrypt(pad(data_to_encrypt, AES.block_size))
            
            # 파일 구조: [마커] + [원본크기] + [암호화크기] + [IV] + [암호화된데이터] + [나머지데이터]
            with open(file_path, 'wb') as f:
                f.write(self.marker)
                f.write(file_size.to_bytes(8, byteorder='big'))
                f.write(encrypt_size.to_bytes(8, byteorder='big'))
                f.write(iv)
                f.write(encrypted_data)
                f.write(remaining_data)
            
            print(f"[+] 암호화 완료: {file_path} ({encrypt_size}/{file_size} bytes)")
            return True
            
        except Exception as e:
            print(f"[!] 암호화 실패 ({file_path}): {str(e)}")
            return False
    
    def decrypt_file(self, file_path):
        """암호화된 파일 복호화"""
        try:
            with open(file_path, 'rb') as f:
                # 마커 확인
                marker = f.read(len(self.marker))
                if marker != self.marker:
                    print(f"[!] 암호화되지 않은 파일: {file_path}")
                    return False
                
                # 메타데이터 읽기
                original_size = int.from_bytes(f.read(8), byteorder='big')
                encrypt_size = int.from_bytes(f.read(8), byteorder='big')
                iv = f.read(16)
                
                # 암호화된 데이터 크기 계산 (패딩 포함)
                padded_size = ((encrypt_size + AES.block_size - 1) // AES.block_size) * AES.block_size
                encrypted_data = f.read(padded_size)
                remaining_data = f.read()
            
            # 복호화
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            
            # 원본 파일 복원
            with open(file_path, 'wb') as f:
                f.write(decrypted_data)
                f.write(remaining_data)
            
            print(f"[+] 복호화 완료: {file_path}")
            return True
            
        except Exception as e:
            print(f"[!] 복호화 실패 ({file_path}): {str(e)}")
            return False
    
    def process_path(self, path, mode, skip_extensions=None):
        """파일 또는 폴더 처리"""
        if skip_extensions is None:
            # 시스템 파일과 실행 파일 제외
            skip_extensions = ['.sys', '.dll', '.exe', '.bat', '.cmd']
        
        if os.path.isfile(path):
            if mode == 'encrypt':
                self.encrypt_file(path)
            else:
                self.decrypt_file(path)
        elif os.path.isdir(path):
            file_count = 0
            skipped = 0
            for root, dirs, files in os.walk(path):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    
                    # 특정 확장자 제외
                    _, ext = os.path.splitext(filename)
                    if ext.lower() in skip_extensions:
                        skipped += 1
                        continue
                    
                    if mode == 'encrypt':
                        if self.encrypt_file(file_path):
                            file_count += 1
                    else:
                        if self.decrypt_file(file_path):
                            file_count += 1
            
            print(f"\n[*] 처리된 파일: {file_count}개")
            if skipped > 0:
                print(f"[*] 제외된 파일: {skipped}개 (시스템 파일)")
        else:
            print(f"[!] 경로를 찾을 수 없음: {path}")

def print_banner():
    """프로그램 배너 출력"""
    print("=" * 70)
    print("         USB 파일 암호화/복호화 도구 (AES-128)")
    print("=" * 70)
    print()

def main():
    print_banner()
    
    # 모드 선택
    print("작업 모드를 선택하세요:")
    print("  1. 암호화 (Encrypt)")
    print("  2. 복호화 (Decrypt)")
    print()
    
    while True:
        choice = input("선택 (1 또는 2): ").strip()
        if choice == '1':
            mode = 'encrypt'
            break
        elif choice == '2':
            mode = 'decrypt'
            break
        else:
            print("[!] 1 또는 2를 입력하세요.")
    
    # 경로 입력
    print()
    print("대상 경로를 입력하세요 (파일 또는 폴더):")
    print("  예시: E:\\SecureFolder")
    print("  예시: E:\\SecureFolder\\document.pdf")
    path = input("경로: ").strip().strip('"')
    
    if not os.path.exists(path):
        print(f"\n[!] 경로가 존재하지 않습니다: {path}")
        input("\n아무 키나 눌러 종료...")
        sys.exit(1)
    
    # 비밀번호 입력
    print()
    password = input("암호 키 입력: ").strip()
    
    if len(password) < 4:
        print("[!] 경고: 비밀번호가 너무 짧습니다 (최소 4자 권장)")
        confirm = input("계속하시겠습니까? (y/n): ")
        if confirm.lower() != 'y':
            sys.exit(0)
    
    # 처리 시작
    print(f"\n{'='*70}")
    print(f"[*] {mode.upper()} 작업 시작...")
    print(f"{'='*70}\n")
    
    encryptor = USBEncryptor(password)
    encryptor.process_path(path, mode)
    
    print(f"\n{'='*70}")
    print("[*] 작업 완료!")
    print(f"{'='*70}")
    input("\n아무 키나 눌러 종료...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] 사용자에 의해 중단되었습니다.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] 오류 발생: {str(e)}")
        input("\n아무 키나 눌러 종료...")
        sys.exit(1)

# pyinstaller --onefile --noconsole --name="USB_Encryptor" --icon=NONE usb_encryptor.py
# pyinstaller --onefile --name="USB_Encryptor" usb_encryptor.py

# pyinstaller --onefile --noconsole --name="USB_Encryptor" usb_encryptor.py
#USB_Encryptor.exe encrypt "D:\USB\SecretFolder" mypassword123
#USB_Encryptor.exe decrypt "D:\USB\SecretFolder" mypassword123
