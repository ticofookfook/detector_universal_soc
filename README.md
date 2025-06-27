# 📁 O que o detector analisa:

## 📄 Microsoft Office:
- `.docx/.docm`, `.xlsx/.xlsm`, `.pptx/.pptm`
- **Detecta:** VBA/Macros maliciosos

## 💻 Scripts:
- `.ps1` (PowerShell), `.bat/.cmd` (Batch), `.vbs` (VBScript), `.js` (JavaScript)
- **Detecta:** Comandos suspeitos, downloads, persistência

## 📋 Documentos:
- `.pdf` (JavaScript embarcado), `.rtf`, `.html/.htm`
- **Detecta:** Ações maliciosas, scripts embarcados

## ⚙️ Executáveis:
- `.exe`, `.dll`, `.scr`
- **Detecta:** Sempre classificados como alto risco + análise de strings

## 📦 Arquivos:
- `.zip`, `.rar`, `.jar`
- **Detecta:** Conteúdo suspeito interno

# 🔍 Capacidades de detecção:
- ✅ Comandos de sistema (cmd.exe, powershell)
- ✅ Downloads maliciosos (XMLHTTP, WebClient)
- ✅ Persistência (Auto_Open, Registry keys)
- ✅ Evasão/Ofuscação (Base64, Chr, Replace)
- ✅ Operações criptográficas (ransomware)
- ✅ Anti-análise (sandbox detection)
- ✅ Padrões regex avançados

# 📊 Classificação de risco:
- **CRITICAL** - Malware confirmado
- **HIGH** - Executáveis e scripts suspeitos
- **MEDIUM** - Potencialmente perigoso
- **LOW** - Atividade suspeita mínima
- **CLEAN** - Sem ameaças detectadas
