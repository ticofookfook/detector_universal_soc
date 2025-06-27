#!/usr/bin/env python3
"""
🔍 DETECTOR UNIVERSAL DE MALWARE PARA SOC
Analisa múltiplos tipos de arquivos em busca de código malicioso:
- Office: .docm, .xlsm, .pptm (VBA/Macros)
- Scripts: .ps1, .bat, .cmd, .vbs, .js
- PDFs: JavaScript embarcado
- Executáveis: .exe, .dll, .scr
- Outros: .zip, .rar, .rtf, .html

Autor: SOC Team  
Versão: 2.0
"""

import os
import sys
import zipfile
import hashlib
import json
import re
import struct
from pathlib import Path
from datetime import datetime
import argparse
import mimetypes

class UniversalMalwareDetector:
    def __init__(self):
        # Palavras-chave suspeitas por categoria
        self.suspicious_keywords = {
            'system_commands': [
                'cmd.exe', 'powershell', 'wscript', 'cscript', 'regsvr32',
                'rundll32', 'mshta', 'certutil', 'bitsadmin', 'wmic',
                'schtasks', 'at.exe', 'sc.exe', 'net.exe', 'taskkill'
            ],
            'network': [
                'XMLHTTP', 'WinHttp', 'URLDownloadToFile', 'InternetOpen',
                'HttpWebRequest', 'WebClient', 'DownloadFile', 'DownloadString',
                'curl', 'wget', 'Invoke-WebRequest', 'Invoke-RestMethod',
                'Start-BitsTransfer', 'ftp', 'tftp', 'telnet'
            ],
            'persistence': [
                'Auto_Open', 'AutoOpen', 'Document_Open', 'Workbook_Open',
                'Auto_Exec', 'AutoExec', 'Auto_Close', 'startup', 'autorun',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
            ],
            'evasion': [
                'Chr(', 'Asc(', 'Replace(', 'Split(', 'Join(', 'Substitute(',
                'Base64', 'FromBase64String', 'ToBase64String', '[Convert]::',
                'Environ(', 'Application.Run', 'CallByName', 'GetObject',
                'eval(', 'execute(', 'setTimeout(', 'setInterval('
            ],
            'crypto': [
                'CryptDecrypt', 'CryptEncrypt', 'AES', 'DES', 'RC4', 'XOR',
                'bitcoin', 'monero', 'ethereum', 'wallet', 'ransomware',
                'encrypted', 'decrypt', 'cipher', 'key', 'payload'
            ],
            'anti_analysis': [
                'Sleep(', 'Application.Wait', 'DoEvents', 'Now()', 'Timer',
                'GetTickCount', 'QueryPerformanceCounter', 'IsDebuggerPresent',
                'CheckRemoteDebuggerPresent', 'GetModuleHandle', 'LoadLibrary',
                'sandbox', 'vm', 'virtual', 'wireshark', 'procmon'
            ]
        }
        
        # Padrões regex de alto risco
        self.high_risk_patterns = [
            r'cmd\.exe\s*/c',
            r'powershell\.exe\s*-[a-zA-Z]+',
            r'CreateObject\s*\(\s*["\']WScript\.Shell["\']',
            r'CreateObject\s*\(\s*["\']Shell\.Application["\']',
            r'http[s]?://[^\s<>"\']+',
            r'\\\\[a-zA-Z0-9\.\-]+\\',  # UNC paths
            r'[A-Za-z]:\\[^\\/:*?"<>|]+',  # Windows paths
            r'\.[exe|bat|scr|vbs|ps1|cmd]["\'\s]',
            r'eval\s*\([^)]+\)',
            r'document\.write\s*\(',
            r'unescape\s*\(',
            r'String\.fromCharCode\s*\('
        ]
        
        # Assinaturas de malware conhecidas (magic bytes)
        self.malware_signatures = {
            b'MZ': 'PE Executable',
            b'PK': 'ZIP/Office Archive',
            b'%PDF': 'PDF Document',
            b'\x7fELF': 'ELF Executable',
            b'\xd0\xcf\x11\xe0': 'OLE2 Document',
            b'JFIF': 'JPEG Image',
            b'\x89PNG': 'PNG Image'
        }

    def detect_file_type(self, file_path):
        """Detecta tipo do arquivo por magic bytes e extensão"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            # Verificar magic bytes
            for magic, file_type in self.malware_signatures.items():
                if header.startswith(magic):
                    return file_type
            
            # Fallback para extensão
            ext = Path(file_path).suffix.lower()
            type_map = {
                '.exe': 'Windows Executable',
                '.dll': 'Windows Library', 
                '.scr': 'Screen Saver',
                '.bat': 'Batch Script',
                '.cmd': 'Command Script',
                '.ps1': 'PowerShell Script',
                '.vbs': 'VBScript',
                '.js': 'JavaScript',
                '.jar': 'Java Archive',
                '.pdf': 'PDF Document',
                '.rtf': 'Rich Text Format',
                '.html': 'HTML Document',
                '.htm': 'HTML Document'
            }
            
            return type_map.get(ext, 'Unknown')
            
        except Exception:
            return 'Unknown'

    def is_supported_file(self, file_path):
        """Verifica se o tipo de arquivo é suportado"""
        supported_extensions = [
            # Office
            '.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm',
            # Scripts  
            '.ps1', '.bat', '.cmd', '.vbs', '.js',
            # Executáveis
            '.exe', '.dll', '.scr',
            # Documentos
            '.pdf', '.rtf', '.html', '.htm',
            # Arquivos
            '.zip', '.rar', '.jar'
        ]
        
        ext = Path(file_path).suffix.lower()
        return ext in supported_extensions

    def analyze_office_file(self, file_path):
        """Análise específica para arquivos Office (VBA/Macros)"""
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                vba_files = [f for f in zip_file.namelist() if 'vbaProject.bin' in f]
                
                if vba_files:
                    vba_content = zip_file.read(vba_files[0])
                    return self.analyze_content(vba_content, 'vba')
                
                # Verificar outros arquivos XML
                suspicious_content = []
                for file_name in zip_file.namelist():
                    if file_name.endswith('.xml') or file_name.endswith('.rels'):
                        try:
                            content = zip_file.read(file_name).decode('utf-8', errors='ignore')
                            analysis = self.analyze_content(content.encode(), 'xml')
                            if analysis['suspicious']:
                                suspicious_content.extend(analysis['suspicious'])
                        except:
                            continue
                
                return {
                    'has_vba': False,
                    'suspicious': suspicious_content,
                    'risk_level': 'LOW' if not suspicious_content else 'MEDIUM'
                }
                
        except Exception as e:
            return {'error': f'Erro ao analisar Office: {e}'}

    def analyze_script_file(self, file_path):
        """Análise para scripts (.ps1, .bat, .vbs, .js)"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            return self.analyze_content(content, 'script')
            
        except Exception as e:
            return {'error': f'Erro ao analisar script: {e}'}

    def analyze_pdf_file(self, file_path):
        """Análise específica para PDFs (JavaScript embarcado)"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            suspicious = []
            
            # Procurar por JavaScript em PDFs
            if b'/JavaScript' in content or b'/JS' in content:
                suspicious.append('PDF with JavaScript')
            
            # Procurar por Launch actions
            if b'/Launch' in content:
                suspicious.append('PDF Launch Action')
            
            # Procurar por URI actions
            if b'/URI' in content:
                suspicious.append('PDF URI Action')
            
            # Análise geral de conteúdo
            general_analysis = self.analyze_content(content, 'pdf')
            suspicious.extend(general_analysis['suspicious'])
            
            risk_level = 'HIGH' if len(suspicious) >= 3 else 'MEDIUM' if suspicious else 'LOW'
            
            return {
                'has_javascript': b'/JavaScript' in content or b'/JS' in content,
                'suspicious': suspicious,
                'risk_level': risk_level
            }
            
        except Exception as e:
            return {'error': f'Erro ao analisar PDF: {e}'}

    def analyze_executable(self, file_path):
        """Análise básica para executáveis"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # Apenas primeiros 1KB
            
            suspicious = []
            
            # Verificar se é PE válido
            if content.startswith(b'MZ'):
                suspicious.append('PE Executable')
                
                # Procurar por strings suspeitas no cabeçalho
                header_str = content.decode('utf-8', errors='ignore')
                if 'cmd.exe' in header_str:
                    suspicious.append('Contains cmd.exe reference')
                if 'powershell' in header_str:
                    suspicious.append('Contains PowerShell reference')
            
            return {
                'is_executable': True,
                'suspicious': suspicious,
                'risk_level': 'HIGH'  # Executáveis sempre são de alto risco
            }
            
        except Exception as e:
            return {'error': f'Erro ao analisar executável: {e}'}

    def analyze_content(self, content, content_type='generic'):
        """Análise genérica de conteúdo para detectar padrões maliciosos"""
        if not content:
            return {'suspicious': [], 'risk_level': 'LOW'}
        
        try:
            content_str = content.decode('utf-8', errors='ignore').lower()
        except:
            content_str = str(content).lower()
        
        suspicious_found = []
        risk_score = 0
        
        # Buscar palavras-chave por categoria
        for category, keywords in self.suspicious_keywords.items():
            category_hits = 0
            for keyword in keywords:
                if keyword.lower() in content_str:
                    suspicious_found.append(f'{category}: {keyword}')
                    category_hits += 1
                    risk_score += 1
            
            # Bônus se muitas palavras da mesma categoria
            if category_hits >= 3:
                risk_score += category_hits
        
        # Buscar padrões regex de alto risco
        for pattern in self.high_risk_patterns:
            matches = re.findall(pattern, content_str, re.IGNORECASE)
            for match in matches:
                suspicious_found.append(f'Pattern: {match}')
                risk_score += 3
        
        # Determinar nível de risco
        if risk_score >= 15:
            risk_level = 'CRITICAL'
        elif risk_score >= 8:
            risk_level = 'HIGH'
        elif risk_score >= 4:
            risk_level = 'MEDIUM'
        elif risk_score >= 1:
            risk_level = 'LOW'
        else:
            risk_level = 'CLEAN'
        
        return {
            'suspicious': list(set(suspicious_found)),
            'risk_level': risk_level,
            'risk_score': risk_score
        }

    def calculate_hash(self, file_path):
        """Calcula hashes MD5 e SHA256"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                md5 = hashlib.md5(content).hexdigest()
                sha256 = hashlib.sha256(content).hexdigest()
                return md5, sha256
        except Exception:
            return None, None

    def analyze_file(self, file_path):
        """Análise completa de qualquer arquivo suportado"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            return {'error': 'Arquivo não encontrado'}
        
        if not self.is_supported_file(str(file_path)):
            return {'error': 'Tipo de arquivo não suportado'}
        
        # Informações básicas
        stat = file_path.stat()
        md5, sha256 = self.calculate_hash(str(file_path))
        file_type = self.detect_file_type(str(file_path))
        
        result = {
            'file_info': {
                'name': file_path.name,
                'path': str(file_path.absolute()),
                'size': stat.st_size,
                'type': file_type,
                'extension': file_path.suffix.lower(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'md5': md5,
                'sha256': sha256
            },
            'timestamp': datetime.now().isoformat()
        }
        
        # Análise específica por tipo
        ext = file_path.suffix.lower()
        
        if ext in ['.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm']:
            analysis = self.analyze_office_file(str(file_path))
        elif ext in ['.ps1', '.bat', '.cmd', '.vbs', '.js']:
            analysis = self.analyze_script_file(str(file_path))
        elif ext == '.pdf':
            analysis = self.analyze_pdf_file(str(file_path))
        elif ext in ['.exe', '.dll', '.scr']:
            analysis = self.analyze_executable(str(file_path))
        else:
            # Análise genérica para outros tipos
            try:
                with open(str(file_path), 'rb') as f:
                    content = f.read()
                analysis = self.analyze_content(content)
            except Exception as e:
                analysis = {'error': f'Erro na análise: {e}'}
        
        result['analysis'] = analysis
        
        # Determinar veredicto final
        if 'error' in analysis:
            result['verdict'] = '❌ ERRO'
        elif analysis.get('risk_level') == 'CRITICAL':
            result['verdict'] = '🚨 CRÍTICO'
        elif analysis.get('risk_level') == 'HIGH':
            result['verdict'] = '⚠️ ALTO RISCO'
        elif analysis.get('risk_level') == 'MEDIUM':
            result['verdict'] = '🔍 SUSPEITO'
        elif analysis.get('risk_level') == 'LOW':
            result['verdict'] = '⚠️ BAIXO RISCO'
        else:
            result['verdict'] = '✅ LIMPO'
        
        return result

    def scan_directory(self, directory, recursive=True):
        """Escaneia diretório em busca de arquivos suportados"""
        directory = Path(directory)
        results = []
        
        pattern = "**/*" if recursive else "*"
        
        for file_path in directory.glob(pattern):
            if file_path.is_file() and self.is_supported_file(str(file_path)):
                print(f"📄 Analisando: {file_path.name}")
                result = self.analyze_file(str(file_path))
                results.append(result)
        
        return results

    def generate_report(self, results, output_file=None):
        """Gera relatório universal de análise"""
        if not results:
            print("❌ Nenhum resultado para gerar relatório")
            return
        
        # Estatísticas
        total_files = len(results)
        critical = sum(1 for r in results if "🚨" in r.get("verdict", ""))
        high_risk = sum(1 for r in results if "⚠️ ALTO RISCO" in r.get("verdict", ""))
        suspicious = sum(1 for r in results if "🔍" in r.get("verdict", ""))
        low_risk = sum(1 for r in results if "⚠️ BAIXO RISCO" in r.get("verdict", ""))
        clean = sum(1 for r in results if "✅" in r.get("verdict", ""))
        errors = sum(1 for r in results if "❌" in r.get("verdict", ""))
        
        # Estatísticas por tipo de arquivo
        file_types = {}
        for result in results:
            if 'error' not in result:
                file_type = result['file_info']['extension']
                file_types[file_type] = file_types.get(file_type, 0) + 1
        
        report = f"""
🔍 RELATÓRIO UNIVERSAL DE ANÁLISE DE MALWARE - SOC
{'='*70}
📊 ESTATÍSTICAS GERAIS:
   Total de arquivos analisados: {total_files}
   🚨 Críticos: {critical}
   ⚠️ Alto Risco: {high_risk}
   🔍 Suspeitos: {suspicious}
   ⚠️ Baixo Risco: {low_risk}
   ✅ Limpos: {clean}
   ❌ Erros: {errors}

📁 TIPOS DE ARQUIVO ANALISADOS:
"""
        
        for ext, count in sorted(file_types.items()):
            report += f"   {ext}: {count} arquivo(s)\n"
        
        report += f"""
📋 DETALHES POR ARQUIVO:
{'='*70}
"""
        
        for result in results:
            if 'error' in result:
                continue
            
            file_info = result['file_info']
            analysis = result['analysis']
            
            report += f"""
📄 ARQUIVO: {file_info['name']}
   📍 Caminho: {file_info['path']}
   📊 Tamanho: {file_info['size']:,} bytes
   🗂️ Tipo: {file_info['type']} ({file_info['extension']})
   🔑 MD5: {file_info['md5']}
   🔑 SHA256: {file_info['sha256']}
   ⚖️ Veredicto: {result['verdict']}
   🎯 Nível de Risco: {analysis.get('risk_level', 'N/A')}
"""
            
            if analysis.get('suspicious'):
                report += "   🚨 Indicadores encontrados:\n"
                for indicator in analysis['suspicious'][:15]:
                    report += f"      • {indicator}\n"
                
                if len(analysis['suspicious']) > 15:
                    report += f"      ... e mais {len(analysis['suspicious']) - 15} indicadores\n"
            
            report += "\n" + "-"*70
        
        report += f"""

📝 RECOMENDAÇÕES DE SEGURANÇA:
• Arquivos CRÍTICOS devem ser quarentenados IMEDIATAMENTE
• Arquivos de ALTO RISCO necessitam análise forense detalhada
• Scripts e executáveis sempre executar em ambiente isolado
• PDFs com JavaScript devem ser analisados em sandbox
• Manter assinaturas de antivírus sempre atualizadas
• Implementar controles de execução de scripts (AppLocker/SRP)

⏰ Relatório gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
🔍 Tipos suportados: Office, Scripts, PDFs, Executáveis, Arquivos
"""
        
        print(report)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n💾 Relatório salvo em: {output_file}")
        
        return report

# Menu interativo (mesmo padrão dos outros scripts)
def interactive_menu():
    """Menu interativo para facilitar o uso"""
    detector = UniversalMalwareDetector()
    
    while True:
        print("\n🔍 DETECTOR UNIVERSAL DE MALWARE - SOC")
        print("=" * 50)
        print("Escolha uma opção:")
        print("1. 📄 Analisar arquivo único")
        print("2. 📁 Escanear diretório atual")
        print("3. 📂 Escanear diretório personalizado")
        print("4. 🔍 Análise em lote (múltiplos arquivos)")
        print("5. 📊 Gerar relatório de análise anterior")
        print("6. ℹ️  Tipos de arquivo suportados")
        print("0. 🚪 Sair")
        
        try:
            choice = input("\nDigite sua opção (0-6): ").strip()
        except KeyboardInterrupt:
            print("\n👋 Saindo...")
            break
        
        if choice == "1":
            analyze_single_file(detector)
        elif choice == "2":
            analyze_current_directory(detector)
        elif choice == "3":
            analyze_custom_directory(detector)
        elif choice == "4":
            analyze_multiple_files(detector)
        elif choice == "5":
            generate_previous_report(detector)
        elif choice == "6":
            show_supported_types()
        elif choice == "0":
            print("👋 Encerrando detector...")
            break
        else:
            print("❌ Opção inválida! Escolha de 0 a 6.")
        
        input("\nPressione ENTER para continuar...")

def show_supported_types():
    """Mostra tipos de arquivo suportados"""
    print("""
📁 TIPOS DE ARQUIVO SUPORTADOS
===============================

📄 MICROSOFT OFFICE:
   • .docx / .docm (Word)
   • .xlsx / .xlsm (Excel)
   • .pptx / .pptm (PowerPoint)
   ➤ Detecção: VBA/Macros maliciosos

💻 SCRIPTS:
   • .ps1 (PowerShell)
   • .bat / .cmd (Batch)
   • .vbs (VBScript)
   • .js (JavaScript)
   ➤ Detecção: Comandos suspeitos, downloads, persistência

📋 DOCUMENTOS:
   • .pdf (PDF Documents)
   • .rtf (Rich Text Format)
   • .html / .htm (HTML)
   ➤ Detecção: JavaScript embarcado, ações suspeitas

⚙️ EXECUTÁVEIS:
   • .exe (Executáveis Windows)
   • .dll (Bibliotecas)
   • .scr (Screen Savers)
   ➤ Detecção: Sempre classificados como alto risco

📦 ARQUIVOS:
   • .zip (Arquivos comprimidos)
   • .rar (WinRAR)
   • .jar (Java Archive)
   ➤ Detecção: Conteúdo suspeito interno

🔍 CAPACIDADES DE DETECÇÃO:
   • Comandos de sistema (cmd, powershell)
   • Downloads de arquivos maliciosos
   • Técnicas de persistência
   • Evasão e ofuscação
   • Operações criptográficas
   • Anti-análise e sandbox evasion
   • Padrões de malware conhecidos
""")

# Funções auxiliares do menu (similares ao script anterior)
def analyze_single_file(detector):
    """Análise de arquivo único"""
    print("\n📄 ANÁLISE DE ARQUIVO ÚNICO")
    print("-" * 30)
    
    file_path = input("Digite o caminho do arquivo: ").strip().strip('"\'')
    
    if not file_path or not os.path.exists(file_path):
        print("❌ Arquivo não encontrado!")
        return
    
    if not detector.is_supported_file(file_path):
        print("❌ Tipo de arquivo não suportado!")
        print("Use a opção 6 para ver tipos suportados.")
        return
    
    print(f"\n🔍 Analisando: {Path(file_path).name}")
    result = detector.analyze_file(file_path)
    
    # Mostrar resultado detalhado
    if "error" in result:
        print(f"❌ Erro na análise: {result['error']}")
        return
    
    print("\n" + "=" * 50)
    print("📊 RESULTADO DA ANÁLISE")
    print("=" * 50)
    
    file_info = result["file_info"]
    analysis = result["analysis"]
    
    print(f"📄 Arquivo: {file_info['name']}")
    print(f"🗂️ Tipo: {file_info['type']} ({file_info['extension']})")
    print(f"📊 Tamanho: {file_info['size']:,} bytes")
    print(f"🔑 MD5: {file_info['md5']}")
    print(f"⚖️ Veredicto: {result['verdict']}")
    print(f"🎯 Nível de Risco: {analysis.get('risk_level', 'N/A')}")
    
    if analysis.get('risk_score'):
        print(f"📊 Score de Risco: {analysis['risk_score']}")
    
    if analysis.get('suspicious'):
        print(f"\n🚨 INDICADORES SUSPEITOS ({len(analysis['suspicious'])}):")
        for i, indicator in enumerate(analysis['suspicious'][:15], 1):
            print(f"   {i:2d}. {indicator}")
        
        if len(analysis['suspicious']) > 15:
            print(f"   ... e mais {len(analysis['suspicious']) - 15} indicadores")
    else:
        print("✅ Nenhum indicador suspeito detectado")
    
    # Opção de salvar relatório
    save = input("\n💾 Salvar relatório detalhado? (s/N): ").strip().lower()
    if save in ['s', 'sim', 'y', 'yes']:
        filename = f"relatorio_{Path(file_path).stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        detector.generate_report([result], filename)

def analyze_current_directory(detector):
    """Análise do diretório atual"""
    print("\n📁 ANÁLISE DO DIRETÓRIO ATUAL")
    print("-" * 35)
    
    current_dir = os.getcwd()
    print(f"📍 Diretório: {current_dir}")
    
    recursive = input("🔄 Busca recursiva em subpastas? (s/N): ").strip().lower()
    recursive = recursive in ['s', 'sim', 'y', 'yes']
    
    print(f"\n🔍 Escaneando {'recursivamente' if recursive else 'apenas nível atual'}...")
    
    results = detector.scan_directory(current_dir, recursive)
    
    if not results:
        print("❌ Nenhum arquivo suportado encontrado!")
        return
    
    show_scan_summary(results)
    post_analysis_options(detector, results)

def analyze_custom_directory(detector):
    """Análise de diretório personalizado"""
    print("\n📂 ANÁLISE DE DIRETÓRIO PERSONALIZADO")
    print("-" * 40)
    
    dir_path = input("Digite o caminho do diretório: ").strip().strip('"\'')
    
    if not dir_path or not os.path.exists(dir_path) or not os.path.isdir(dir_path):
        print("❌ Diretório não encontrado ou inválido!")
        return
    
    recursive = input("🔄 Busca recursiva em subpastas? (s/N): ").strip().lower()
    recursive = recursive in ['s', 'sim', 'y', 'yes']
    
    print(f"\n🔍 Escaneando {dir_path} {'recursivamente' if recursive else 'apenas nível atual'}...")
    
    results = detector.scan_directory(dir_path, recursive)
    
    if not results:
        print("❌ Nenhum arquivo suportado encontrado!")
        return
    
    show_scan_summary(results)
    post_analysis_options(detector, results)

def analyze_multiple_files(detector):
    """Análise em lote de múltiplos arquivos"""
    print("\n🔍 ANÁLISE EM LOTE")
    print("-" * 20)
    
    print("Digite os caminhos dos arquivos (um por linha).")
    print("Digite uma linha vazia para finalizar:")
    
    files = []
    while True:
        file_path = input("Arquivo: ").strip().strip('"\'')
        if not file_path:
            break
        files.append(file_path)
    
    if not files:
        print("❌ Nenhum arquivo fornecido!")
        return
    
    results = []
    print(f"\n🔍 Analisando {len(files)} arquivo(s)...")
    
    for file_path in files:
        if not os.path.exists(file_path):
            print(f"❌ Não encontrado: {file_path}")
            continue
        
        if not detector.is_supported_file(file_path):
            print(f"⚠️ Não suportado: {file_path}")
            continue
        
        print(f"📄 Analisando: {Path(file_path).name}")
        result = detector.analyze_file(file_path)
        results.append(result)
    
    if results:
        show_scan_summary(results)
        post_analysis_options(detector, results)
    else:
        print("❌ Nenhum arquivo válido foi analisado!")

def show_scan_summary(results):
    """Mostra resumo da análise"""
    total = len(results)
    critical = sum(1 for r in results if "🚨" in r.get("verdict", ""))
    high_risk = sum(1 for r in results if "⚠️ ALTO RISCO" in r.get("verdict", ""))
    suspicious = sum(1 for r in results if "🔍" in r.get("verdict", ""))
    low_risk = sum(1 for r in results if "⚠️ BAIXO RISCO" in r.get("verdict", ""))
    clean = sum(1 for r in results if "✅" in r.get("verdict", ""))
    errors = sum(1 for r in results if "❌" in r.get("verdict", ""))
    
    print(f"\n📊 RESUMO DA ANÁLISE")
    print("=" * 30)
    print(f"📁 Total analisado: {total}")
    print(f"🚨 Críticos: {critical}")
    print(f"⚠️ Alto Risco: {high_risk}")
    print(f"🔍 Suspeitos: {suspicious}")
    print(f"⚠️ Baixo Risco: {low_risk}")
    print(f"✅ Limpos: {clean}")
    if errors > 0:
        print(f"❌ Erros: {errors}")
    
    # Mostrar arquivos por categoria de risco
    if critical > 0:
        print(f"\n🚨 ARQUIVOS CRÍTICOS:")
        for r in results:
            if "🚨" in r.get("verdict", ""):
                print(f"   • {r['file_info']['name']}")
    
    if high_risk > 0:
        print(f"\n⚠️ ARQUIVOS DE ALTO RISCO:")
        for r in results:
            if "⚠️ ALTO RISCO" in r.get("verdict", ""):
                print(f"   • {r['file_info']['name']}")
    
    if suspicious > 0:
        print(f"\n🔍 ARQUIVOS SUSPEITOS:")
        for r in results:
            if "🔍" in r.get("verdict", ""):
                print(f"   • {r['file_info']['name']}")

def post_analysis_options(detector, results):
    """Opções após análise"""
    print(f"\n📋 OPÇÕES PÓS-ANÁLISE")
    print("1. 📄 Ver relatório completo")
    print("2. 💾 Salvar relatório em arquivo")
    print("3. 💾 Exportar dados JSON")
    print("4. 🔍 Ver detalhes de arquivo específico")
    print("5. ⬅️ Voltar ao menu principal")
    
    choice = input("\nEscolha uma opção (1-5): ").strip()
    
    if choice == "1":
        detector.generate_report(results)
    elif choice == "2":
        filename = input("Nome do arquivo (ou ENTER para automático): ").strip()
        if not filename:
            filename = f"relatorio_universal_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        detector.generate_report(results, filename)
    elif choice == "3":
        filename = input("Nome do arquivo JSON (ou ENTER para automático): ").strip()
        if not filename:
            filename = f"dados_universal_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"💾 Dados JSON salvos em: {filename}")
    elif choice == "4":
        show_file_details(results)
    elif choice == "5":
        return
    else:
        print("❌ Opção inválida!")

def show_file_details(results):
    """Mostra detalhes de arquivo específico"""
    print(f"\n📄 ARQUIVOS DISPONÍVEIS:")
    for i, result in enumerate(results, 1):
        if "error" not in result:
            name = result['file_info']['name']
            file_type = result['file_info']['extension']
            verdict = result['verdict']
            print(f"   {i:2d}. {name} ({file_type}) - {verdict}")
    
    try:
        choice = int(input("\nNúmero do arquivo para detalhes: "))
        if 1 <= choice <= len(results):
            result = results[choice - 1]
            if "error" in result:
                print("❌ Arquivo com erro!")
                return
            
            # Mostrar detalhes completos
            file_info = result["file_info"]
            analysis = result["analysis"]
            
            print(f"\n📄 DETALHES: {file_info['name']}")
            print("=" * 50)
            print(f"📍 Caminho: {file_info['path']}")
            print(f"🗂️ Tipo: {file_info['type']} ({file_info['extension']})")
            print(f"📊 Tamanho: {file_info['size']:,} bytes")
            print(f"📅 Modificado: {file_info['modified']}")
            print(f"🔑 MD5: {file_info['md5']}")
            print(f"🔑 SHA256: {file_info['sha256']}")
            print(f"⚖️ Veredicto: {result['verdict']}")
            print(f"🎯 Nível de Risco: {analysis.get('risk_level', 'N/A')}")
            
            if analysis.get('risk_score'):
                print(f"📊 Score de Risco: {analysis['risk_score']}")
            
            if analysis.get('suspicious'):
                print(f"\n🚨 INDICADORES SUSPEITOS ({len(analysis['suspicious'])}):")
                for indicator in analysis['suspicious']:
                    print(f"   • {indicator}")
            else:
                print("\n✅ Nenhum indicador suspeito detectado")
        else:
            print("❌ Número inválido!")
    except ValueError:
        print("❌ Digite um número válido!")

def generate_previous_report(detector):
    """Gerar relatório de análise anterior"""
    print("\n📊 GERAR RELATÓRIO DE ANÁLISE ANTERIOR")
    print("-" * 45)
    print("Esta opção permite gerar relatório de dados JSON salvos anteriormente.")
    
    json_file = input("Caminho do arquivo JSON: ").strip().strip('"\'')
    
    if not json_file or not os.path.exists(json_file):
        print("❌ Arquivo JSON não encontrado!")
        return
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            results = json.load(f)
        
        print(f"📄 Carregados {len(results)} resultado(s) do arquivo JSON")
        detector.generate_report(results)
        
        save = input("\n💾 Salvar relatório em arquivo? (s/N): ").strip().lower()
        if save in ['s', 'sim', 'y', 'yes']:
            filename = f"relatorio_json_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            detector.generate_report(results, filename)
            
    except Exception as e:
        print(f"❌ Erro ao carregar JSON: {e}")

def main():
    """Função principal com suporte a argumentos e menu interativo"""
    if len(sys.argv) > 1:
        # Modo linha de comando
        parser = argparse.ArgumentParser(
            description="🔍 Detector Universal de Malware para SOC",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Exemplos de uso:
  python universal_detector.py arquivo.exe
  python universal_detector.py -d /caminho/diretorio -r
  python universal_detector.py script.ps1 documento.pdf
  python universal_detector.py --interactive  # Menu interativo
            """
        )
        
        parser.add_argument('files', nargs='*', help='Arquivos para analisar')
        parser.add_argument('-d', '--directory', help='Diretório para escanear')
        parser.add_argument('-r', '--recursive', action='store_true', 
                           help='Escaneamento recursivo de diretórios')
        parser.add_argument('-o', '--output', help='Arquivo de saída do relatório')
        parser.add_argument('-j', '--json', help='Salvar resultados em JSON')
        parser.add_argument('-i', '--interactive', action='store_true',
                           help='Modo interativo com menu')
        
        args = parser.parse_args()
        
        if args.interactive:
            interactive_menu()
            return
        
        detector = UniversalMalwareDetector()
        all_results = []
        
        print("🔍 DETECTOR UNIVERSAL DE MALWARE - SOC")
        print("="*60)
        
        # Analisar arquivos individuais
        if args.files:
            for file_pattern in args.files:
                from glob import glob
                files = glob(file_pattern)
                
                if not files:
                    print(f"❌ Arquivo não encontrado: {file_pattern}")
                    continue
                
                for file_path in files:
                    if detector.is_supported_file(file_path):
                        print(f"📄 Analisando: {Path(file_path).name}")
                        result = detector.analyze_file(file_path)
                        all_results.append(result)
                    else:
                        print(f"⚠️ Tipo não suportado: {file_path}")
        
        # Analisar diretório
        if args.directory:
            results = detector.scan_directory(args.directory, args.recursive)
            all_results.extend(results)
        
        # Gerar relatórios
        if all_results:
            print(f"\n✅ Análise concluída! {len(all_results)} arquivo(s) processado(s)")
            
            detector.generate_report(all_results, args.output)
            
            if args.json:
                with open(args.json, 'w', encoding='utf-8') as f:
                    json.dump(all_results, f, indent=2, ensure_ascii=False)
                print(f"💾 Dados JSON salvos em: {args.json}")
        else:
            print("❌ Nenhum arquivo válido encontrado para análise")
    else:
        # Modo interativo (padrão)
        interactive_menu()

if __name__ == "__main__":
    main()
