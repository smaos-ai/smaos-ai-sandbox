# КОНЦЕПТУАЛЬНА ЗАПИСКА / CONCEPT NOTE
## Пропозиція щодо майбутнього академічного та наукового співробітництва
## Proposed Future Academic and Scientific Cooperation
***Лише для обговорення — не є обов’язковим документом — не для підписання***
***For discussion only — non-binding — not for signature***

---

### 1. Контекст та мета / Context & Purpose

| Українська версія (Ukrainian) | English Version |
| :--- | :--- |
| Ця Концептуальна записка підготовлена **Андрієм ЛЕУХІНОМ** (випускником НУ «Львівська політехніка») з метою вивчення можливостей майбутньої академічної та наукової співпраці між **Національним університетом «Львівська політехніка» (вул. С. Бандери, 12, м. Львів, 79013, Україна)** та чеською технологічною компанією, яка перебуває на завершальній стадії реєстрації (**провезорична назва: SovereignNexus s.r.o.**). | This Concept Note is prepared by **Andrii LEUKHIN** (LPNU Alumnus) to explore a potential future academic and scientific collaboration between **Lviv Polytechnic National University (12 Stepan Bandera Street, Lviv 79013, Ukraine)** and a Czech technology company in the final stage of incorporation (**provisional name: SovereignNexus s.r.o.**). |
| Мета цього документа є виключно попередньою та ознайомчою: | The purpose of this document is purely preliminary and exploratory: |
| • Представити дослідницький напрям: **надійність програмного забезпечення, фіналізація виконання (execution finality), обробка збоїв та цілісність доказів (evidence integrity) для автономних систем штучного інтелекту**. | • To introduce the research domain: **software reliability, execution finality, fault handling, and evidence integrity for autonomous AI systems**. |
| • Запросити рекомендації НУ «Львівська політехніка» щодо офіційних процедур міжнародного співробітництва, затверджених інституційних шаблонів Меморандумів про взаєморозуміння (MoU), а також контактів відповідних академічних, юридичних підрозділів та відділу трансферу технологій. | • To request LPNU's guidance regarding its official international cooperation procedures, approved institutional MoU templates, and relevant academic, legal, and technology-transfer contacts. |
| • **Цей документ не є договором чи угодою, не створює жодних юридичних чи фінансових зобов'язань і не призначений для підписання.** Документ передається виключно для сприяння початковому інституційному діалогу та запиту офіційного шаблону співпраці НУ «Львівська політехніка». | • **This document is not a contract or agreement, creates no legal or financial obligations, and is not for signature.** This document is shared solely to facilitate an initial institutional conversation and to request LPNU’s official cooperation template and routing guidance. |

---

### 2. Запропонований дослідницький напрям / Proposed Research Domain

| Українська версія (Ukrainian) | English Version |
| :--- | :--- |
| У зв'язку зі швидким глобальним впровадженням автономних середовищ виконання AI-агентів виникають критичні виклики у розподілених системах, пов'язані з обробкою збоїв на транспортному рівні, недетермінованими циклами виконання та невизначеністю стану після передачі даних (наприклад, таймаути HTTP 504). | With the rapid global deployment of autonomous AI agent runtimes, critical distributed-systems challenges have emerged around transport-layer fault handling, non-deterministic execution loops, and post-transmission state ambiguity (e.g., HTTP 504 timeouts). |
| Потенційна майбутня співпраця може бути зосереджена на: | Potential future collaboration could focus on: |
| • **Бенчмаркінг та оцінка**: Незалежне академічне відтворення та методологічна критика відкритих бенчмарк-фреймворків (таких як Agent Effect Integrity Benchmark — AEIB). | • **Benchmark Evaluation**: Independent academic reproduction and methodological critique of open-source benchmark frameworks (such as the Agent Effect Integrity Benchmark - AEIB). |
| • **Формальна верифікація**: Дослідження фіналізації виконання, детермінованого логування стану та ізоляції на рівні ядра (наприклад, eBPF / XDP). | • **Formal Verification**: Research into execution finality, deterministic state logging, and kernel-level isolation primitives (e.g., eBPF / XDP). |
| • **Ґрантове співробітництво**: Спільне вивчення європейських та міжнародних безбюджетних дослідницьких конкурсів (наприклад, Horizon Europe, НФД) після офіційного заснування юридичної особи. | • **Grant Collaboration**: Joint exploration of European and international non-funded research calls (e.g., Horizon Europe, NRFU) upon formal entity setup. |

---

### 3. Чіткі операційні та адміністративні межі / Strict Operational Boundaries

| Українська версія (Ukrainian) | English Version |
| :--- | :--- |
| Для забезпечення повної інституційної безпеки та відсутності бюрократичного тертя під час початкових обговорень, будь-який майбутній проект дотримуватиметься таких принципів: | To ensure zero friction and complete institutional safety during initial discussions, any future project shall adhere to the following principles: |
| 1. **Виключно синтетичні та публічні дані**: 100% оцінки бенчмарків використовує публічні набори сценаріїв та синтетичні траси ін'єкції збоїв. Персональні дані (PII), записи клієнтів або операційні дані університету ніколи не завантажуватимуться і не оброблятимуться. | 1. **Synthetic & Public Data Only**: 100% of benchmark evaluation uses public scenario corpora and synthetic fault-injection traces. No PII, customer records, or university operational data will ever be ingested or processed. |
| 2. **Нульовий доступ до продакшн-систем**: Відсутність будь-якого доступу до продуктивних баз даних, живих IT-мереж чи сховищ облікових даних. | 2. **Zero Production Access**: No access to production databases, live IT networks, or credential stores. |
| 3. **Відсутність фінансових зобов'язань**: Експлораторна фаза є безбюджетною, де кожен учасник самостійно покриває свої адміністративні витрати. | 3. **No Financial Obligations**: The exploratory phase is non-funded, with each participant bearing its own administrative costs. |
| 4. **Повний захист інтелектуальної власності**: Фонова інтелектуальна власність (Background IP) залишається у 100% власності її первинного власника. Права на публікації та нова IP (Foreground IP) регулюватимуться окремими офіційними Проєктними Додатками (Project Annexes), підписаними до початку робіт. | 4. **Complete IP Protection**: Pre-existing Background Intellectual Property remains fully owned by its originating owner. Publication rights and Foreground IP will be governed by specific, formal Project Annexes signed prior to work starting. |
| 5. **Заборона комерційного маркетингу**: Жодних публічних заявою, використання логотипів чи заявою про комерційне партнерство без письмової згоди керівництва університету. | 5. **No Commercial Marketing Claims**: No public announcements, logo usage, or commercial partnership claims will be made without explicit, written institutional consent. |

---

### 4. Дорожня карта формалізації / Roadmap to Formalization

```text
┌────────────────────────────────┐
│ 1. Реєстрація компанії         │ Завершення реєстрації чеської юридичної особи (IČO)
└───────────────┬────────────────┘
                │
┌───────────────▼────────────────┐
│ 2. Офіційний шаблон НУ «ЛП»    │ Університет надає офіційний шаблон MoU та контакти
└───────────────┬────────────────┘
                │
┌───────────────▼────────────────┐
│ 3. Юридичний аналіз            │ Двомовна юридична перевірка проекту (чеське та українське право)
└───────────────┬────────────────┘
                │
┌───────────────▼────────────────┐
│ 4. Підписання MoU та Додатка   │ Підписання рамкового MoU та вузького синтетичного AEIB Додатка
└────────────────────────────────┘
```

---

### 5. Інституційний запит / Institutional Contact Request

| Українська версія (Ukrainian) | English Version |
| :--- | :--- |
| НУ «Львівська політехніка» пропонується надати: | LPNU is kindly invited to share: |
| • Офіційний затверджений шаблон Меморандуму про взаєморозуміння (MoU) для міжнародного співробітництва. | • The official LPNU template for international Memoranda of Understanding (MoU). |
| • Контактні дані відповідних наукових керівників у сферах ШІ/Кібербезпеки, Відділу міжнародних зв'язків та Відділу трансферу технологій. | • Contact details for the appropriate academic leads in AI/Cybersecurity, International Relations Office, and Technology Transfer Office. |
| **Очікуваний наступний крок** — коротка ознайомча онлайн-зустріч або обмін листами з відповідним підрозділом НУ «Львівська політехніка» для розуміння стандартної процедури міжнародного академічного співробітництва. | **The expected next step** is a brief introductory call or email exchange with the appropriate LPNU office to understand the standard procedure for international academic cooperation. |

---

*Підготовлено / Prepared by:*  
**Андрій ЛЕУХІН / Andrii LEUKHIN**  
*(м. Прага, Чеська Республіка / Випускник НУ «Львівська політехніка»)*  
*Email: andrejlo123@gmail.com | Вересень / September 2026*
