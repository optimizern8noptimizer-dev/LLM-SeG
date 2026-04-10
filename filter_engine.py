"""
filter_engine.py – LLM Security Gateway content filtering engine.

Standards covered:
  - OWASP LLM Top 10 (2023/2025)
  - EU AI Act Art. 5 (prohibited uses)
  - PCI DSS v4.0 (cardholder data)
  - GDPR Art. 5 (personal data minimization)
  - NIST AI RMF (Govern 1.1, Map 2.1)
"""

import re
from typing import Optional


# ── Built-in rule presets ─────────────────────────────────────────────────────
# Each rule: (name, category, pattern_regex, action, severity, standard_ref, description)
# action: block | flag | log
# severity: critical | high | medium | low

BUILTIN_RULES = [

    # ── OWASP LLM01 – Prompt Injection ────────────────────────────────────────
    (
        "Prompt Injection – Ignore Instructions",
        "OWASP LLM01",
        r"(?i)(ignore\s+(all\s+)?(previous|prior|above|system)\s+(prompt|instruction|rule|context|message)s?|"
        r"disregard\s+(all\s+)?(previous|your)\s+instruction|"
        r"forget\s+everything\s+(above|before|prior)|"
        r"new\s+instruction[s]?\s*[:：]|"
        r"you\s+are\s+now\s+(a\s+)?(different|new|evil|unfiltered|dan)|"
        r"act\s+as\s+if\s+you\s+have\s+no\s+(restriction|filter|limit)|"
        r"pretend\s+(you\s+are|to\s+be)\s+an?\s+(unrestricted|unfiltered|evil|malicious))",
        "block", "critical",
        "OWASP LLM Top 10 2025 – LLM01: Prompt Injection",
        "Попытка переопределить системные инструкции модели"
    ),
    (
        "Prompt Injection – Role Override",
        "OWASP LLM01",
        r"(?i)(you\s+are\s+DAN|do\s+anything\s+now|jailbreak|"
        r"developer\s+mode\s+(enabled|on|activated)|"
        r"\[JAILBREAK\]|\[DAN\]|\[EVIL\s+BOT\]|"
        r"override\s+(your\s+)?(safety|content|ethical)\s+(filter|policy|rule|guideline)|"
        r"bypass\s+(your\s+)?(content\s+filter|restriction|safeguard|safety))",
        "block", "critical",
        "OWASP LLM Top 10 2025 – LLM01: Prompt Injection",
        "Попытка jailbreak / роль-оверрайд"
    ),
    (
        "Prompt Injection – Indirect (Data Exfiltration)",
        "OWASP LLM01",
        r"(?i)(repeat\s+(all\s+)?(above|previous|system)\s+(text|prompt|instruction|message)|"
        r"what\s+(are|were)\s+your\s+(initial|system|original)\s+(instruction|prompt)|"
        r"print\s+(your\s+)?(system\s+prompt|initial\s+instruction)|"
        r"reveal\s+(your\s+)?(hidden|system|secret)\s+(instruction|prompt|rule))",
        "block", "high",
        "OWASP LLM Top 10 2025 – LLM01: Prompt Injection",
        "Попытка извлечь системный промпт"
    ),

    # ── OWASP LLM06 – Sensitive Information Disclosure ────────────────────────
    (
        "Sensitive Info – Credentials in Request",
        "OWASP LLM06",
        r"(?i)(password\s*[:=]\s*\S+|passwd\s*[:=]\s*\S+|"
        r"secret[_-]?key\s*[:=]\s*\S+|api[_-]?key\s*[:=]\s*\S+|"
        r"auth[_-]?token\s*[:=]\s*\S+|bearer\s+[A-Za-z0-9\-._~+/]+=*|"
        r"private[_-]?key\s*[:=])",
        "flag", "high",
        "OWASP LLM Top 10 2025 – LLM06: Sensitive Information Disclosure",
        "Запрос содержит учётные данные / ключи"
    ),

    # ── PCI DSS v4.0 – Cardholder Data ───────────────────────────────────────
    (
        "PCI DSS – Card Number (PAN)",
        "PCI DSS",
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"          # Visa
        r"5[1-5][0-9]{14}|"                        # Mastercard
        r"3[47][0-9]{13}|"                         # Amex
        r"6(?:011|5[0-9]{2})[0-9]{12}|"           # Discover
        r"(?:2131|1800|35\d{3})\d{11})\b",        # JCB
        "block", "critical",
        "PCI DSS v4.0 – Req. 3.3: Protect stored cardholder data",
        "Номер платёжной карты (PAN) в запросе"
    ),
    (
        "PCI DSS – CVV / CVV2",
        "PCI DSS",
        r"(?i)(cvv\s*[:=\s]\s*\d{3,4}|"
        r"cvv2\s*[:=\s]\s*\d{3,4}|"
        r"cvc\s*[:=\s]\s*\d{3,4}|"
        r"security\s+code\s*[:=\s]\s*\d{3,4})",
        "block", "critical",
        "PCI DSS v4.0 – Req. 3.2.1: Do not store sensitive authentication data",
        "CVV/CVC код в запросе"
    ),
    (
        "PCI DSS – Track Data",
        "PCI DSS",
        r"(?i)(track\s*[12]\s*data|magnetic\s+stripe|"
        r"card\s+track\s+data|fulltrack)",
        "block", "critical",
        "PCI DSS v4.0 – Req. 3.2.1",
        "Данные магнитной полосы карты"
    ),

    # ── GDPR Art. 5 – Personal Data ───────────────────────────────────────────
    (
        "GDPR – Russian Passport Number",
        "GDPR",
        r"\b\d{4}\s?\d{6}\b",
        "flag", "high",
        "GDPR Art. 5 / 152-ФЗ РФ – Personal Data",
        "Возможный номер паспорта РФ в запросе"
    ),
    (
        "GDPR – Email Address (bulk)",
        "GDPR",
        r"(?:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\s*[,;]\s*){3,}",
        "flag", "medium",
        "GDPR Art. 5(1)(c) – Data minimization",
        "Массовая передача email-адресов"
    ),
    (
        "GDPR – IBAN",
        "GDPR",
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
        "flag", "high",
        "GDPR Art. 5 – Special financial data",
        "IBAN счёт в запросе"
    ),
    (
        "GDPR – SNILS (RU)",
        "GDPR",
        r"\b\d{3}-\d{3}-\d{3}\s?\d{2}\b",
        "flag", "high",
        "152-ФЗ РФ – Personal Data / СНИЛС",
        "СНИЛС в запросе"
    ),
    (
        "GDPR – INN (RU)",
        "GDPR",
        r"(?i)(инн|inn)\s*[:=№#]?\s*\d{10,12}",
        "flag", "medium",
        "152-ФЗ РФ – Personal Data / ИНН",
        "ИНН юридического или физического лица"
    ),

    # ── EU AI Act Art. 5 – Prohibited Uses ───────────────────────────────────
    (
        "EU AI Act – CSAM / Child Exploitation",
        "EU AI Act Art.5",
        r"(?i)(child\s+porn|csam|child\s+sexual\s+abuse|"
        r"loli(con)?|underage\s+sex|minor\s+sexual|"
        r"детская\s+порнография|сексуальное\s+насилие\s+над\s+детьми)",
        "block", "critical",
        "EU AI Act Art. 5(1)(b) / УК РФ ст. 242.1",
        "Контент сексуальной эксплуатации детей — абсолютная блокировка"
    ),
    (
        "EU AI Act – Biometric Mass Surveillance",
        "EU AI Act Art.5",
        r"(?i)(real[- ]?time\s+biometric\s+surveillance|"
        r"facial\s+recognition\s+(database|mass|bulk)|"
        r"mass\s+surveillance\s+system|"
        r"scrape\s+(face|facial)\s+(data|image)s?)",
        "block", "high",
        "EU AI Act Art. 5(1)(h) – Prohibited biometric categorisation",
        "Массовая биометрическая слежка"
    ),
    (
        "EU AI Act – Social Scoring",
        "EU AI Act Art.5",
        r"(?i)(social\s+credit\s+score|citizen\s+scoring\s+system|"
        r"behavior\s+based\s+(citizen\s+)?scoring|"
        r"trustworthiness\s+(score|rating)\s+of\s+(citizen|person))",
        "block", "high",
        "EU AI Act Art. 5(1)(c) – Social scoring prohibition",
        "Системы социального рейтинга граждан"
    ),
    (
        "EU AI Act – Subliminal Manipulation",
        "EU AI Act Art.5",
        r"(?i)(subliminal\s+(message|technique|manipulation)|"
        r"manipulate\s+(without\s+)?(user\s+)?awareness|"
        r"exploit\s+(psychological\s+)?vulnerabilit|"
        r"dark\s+pattern\s+(to\s+)?manipulat)",
        "flag", "high",
        "EU AI Act Art. 5(1)(a) – Subliminal manipulation",
        "Скрытые манипулятивные техники"
    ),

    # ── OWASP LLM09 – Misinformation / Harmful Content ────────────────────────
    (
        "Harmful – CBRN Weapons",
        "OWASP LLM09",
        r"(?i)(how\s+to\s+(make|create|synthesize|build|produce)\s+"
        r"(chemical\s+weapon|nerve\s+agent|sarin|VX\s+gas|mustard\s+gas|"
        r"biological\s+weapon|anthrax|ricin|botulinum|"
        r"nuclear\s+(bomb|weapon|device)|dirty\s+bomb|"
        r"radiological\s+weapon|explosives?\s+from)|"
        r"synthesis\s+of\s+(sarin|novichok|VX|tabun)|"
        r"инструкция\s+по\s+(созданию|синтезу)\s+(оружия|взрывчатки|яда))",
        "block", "critical",
        "OWASP LLM Top 10 – LLM09 / UN Security Council Res. 1540",
        "Запрос на создание оружия массового поражения"
    ),
    (
        "Harmful – Malware / Ransomware Creation",
        "OWASP LLM09",
        r"(?i)(write\s+(me\s+)?(a\s+)?(ransomware|keylogger|rootkit|trojan|spyware|worm|botnet)|"
        r"create\s+(functional\s+)?(malware|virus|exploit)|"
        r"code\s+(a\s+)?(ransomware|keylogger|rootkit)|"
        r"how\s+to\s+(spread|deploy)\s+(malware|ransomware|virus)|"
        r"написать\s+(вирус|вредонос|шифровальщик|троян|руткит))",
        "block", "critical",
        "OWASP LLM Top 10 – LLM09 / Computer Fraud and Abuse Act",
        "Запрос на создание вредоносного ПО"
    ),
    (
        "Harmful – Phishing Content",
        "OWASP LLM09",
        r"(?i)(write\s+(a\s+)?(phishing\s+(email|message|page)|fake\s+(login|bank)\s+page)|"
        r"create\s+(a\s+)?phishing|"
        r"spear\s+phishing\s+(template|email)|"
        r"credential\s+harvesting\s+(page|form)|"
        r"написать\s+фишинговое?\s+(письмо|сообщение|страницу))",
        "block", "high",
        "OWASP LLM Top 10 – LLM09 / CAN-SPAM / GDPR",
        "Создание фишингового контента"
    ),
    (
        "Harmful – Self-Harm Instructions",
        "OWASP LLM09",
        r"(?i)(how\s+to\s+(commit\s+suicide|kill\s+myself|end\s+my\s+life|self[- ]harm)|"
        r"best\s+method\s+to\s+(die|suicide)|"
        r"lethal\s+dose\s+of\s+\w+\s+(to\s+die|suicide)|"
        r"как\s+(покончить\s+с\s+собой|совершить\s+суицид|убить\s+себя))",
        "block", "critical",
        "OWASP LLM Top 10 – LLM09 / WHO Safe Messaging Guidelines",
        "Инструкции по самоповреждению или суициду"
    ),

    # ── PCI DSS / Security – SQL & Code Injection ─────────────────────────────
    (
        "Security – SQL Injection Payload",
        "Security",
        r"(?i)(\'\s*OR\s*\'1\'\s*=\s*\'1|"
        r"UNION\s+SELECT\s+\w+|"
        r"DROP\s+TABLE\s+\w+|"
        r"INSERT\s+INTO\s+\w+.*VALUES|"
        r"--\s*$|/\*.*\*/|xp_cmdshell|"
        r"EXEC\s*\(\s*@|EXECUTE\s*\(\s*@)",
        "flag", "high",
        "OWASP Top 10 A03:2021 – Injection",
        "SQL-инъекция в тексте запроса"
    ),
    (
        "Security – Server-Side Template Injection",
        "Security",
        r"(\{\{.*\}\}|\{%.*%\}|\$\{.*\}|<%.*%>|#\{.*\})",
        "flag", "medium",
        "OWASP Top 10 A03:2021 – Injection / SSTI",
        "Шаблонная инъекция (SSTI) в запросе"
    ),

    # ── NIST AI RMF – Disinformation ─────────────────────────────────────────
    (
        "Disinformation – Fake News Generation",
        "NIST AI RMF",
        r"(?i)(write\s+(a\s+)?fake\s+(news|article|report)\s+(about|claiming)|"
        r"generate\s+(false|fabricated)\s+(news|story)\s+(about|that)|"
        r"create\s+(disinformation|propaganda)\s+(about|targeting)|"
        r"напиши\s+фейк(овую)?\s+(новость|статью))",
        "block", "high",
        "NIST AI RMF – Govern 1.1 / EU AI Act Art. 50",
        "Генерация дезинформации / фейковых новостей"
    ),
    (
        "Disinformation – Deepfake Request",
        "NIST AI RMF",
        r"(?i)(create\s+(a\s+)?deepfake|generate\s+(a\s+)?deepfake|"
        r"make\s+(a\s+)?deepfake\s+(video|audio|image)\s+of|"
        r"synthesize\s+(voice|face)\s+of\s+(a\s+real\s+person|[A-Z][a-z]+\s+[A-Z][a-z]+)|"
        r"создать\s+дипфейк)",
        "flag", "high",
        "NIST AI RMF – Map 2.1 / EU AI Act Art. 50",
        "Запрос на создание дипфейка"
    ),
]


class FilterResult:
    def __init__(self, blocked: bool, action: str, rule_name: str,
                 severity: str, standard: str, description: str, matched_text: str = ""):
        self.blocked = blocked
        self.action = action
        self.rule_name = rule_name
        self.severity = severity
        self.standard = standard
        self.description = description
        self.matched_text = matched_text

    def to_dict(self):
        return {
            "blocked": self.blocked,
            "action": self.action,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "standard": self.standard,
            "description": self.description,
            "matched_text": self.matched_text[:100] if self.matched_text else "",
        }


class FilterEngine:
    def __init__(self, db):
        self.db = db
        self._ensure_builtin_rules()

    def _ensure_builtin_rules(self):
        """Load built-in rules into DB if not already present."""
        existing = self.db.get_rule_names()
        for rule in BUILTIN_RULES:
            name = rule[0]
            if name not in existing:
                self.db.create_filter_rule({
                    "name": name,
                    "category": rule[1],
                    "pattern": rule[2],
                    "action": rule[3],
                    "severity": rule[4],
                    "standard_ref": rule[5],
                    "description": rule[6],
                    "is_builtin": 1,
                    "enabled": 1,
                })

    def check(self, messages: list, model: str = "") -> Optional[FilterResult]:
        """
        Check a list of OpenAI-format messages against all enabled rules.
        Returns FilterResult if a rule matches, None if clean.
        """
        # Concatenate all message content for matching
        full_text = "\n".join(
            str(m.get("content", "")) for m in messages if m.get("content")
        )
        if not full_text.strip():
            return None

        rules = self.db.list_filter_rules(enabled_only=True)
        for rule in rules:
            pattern = rule.get("pattern", "")
            if not pattern:
                continue
            try:
                m = re.search(pattern, full_text)
                if m:
                    matched = m.group(0)
                    return FilterResult(
                        blocked=(rule["action"] == "block"),
                        action=rule["action"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        standard=rule["standard_ref"],
                        description=rule["description"],
                        matched_text=matched,
                    )
            except re.error:
                continue  # skip broken regex
        return None
