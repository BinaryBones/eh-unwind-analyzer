# Том III. Точность, валидация и проектирование строгого эксперимента

## Почему вопрос «какова точность» неполон

Точность нельзя вычислить, пока не определены:

1. единица классификации;
2. положительный класс;
3. отрицательный класс;
4. ground truth;
5. threshold решения;
6. состав corpus;
7. правила учёта неоднозначных cases.

Для EH/Unwind Analyzer возможны разные задачи:

- определить, разбирается ли PE без structural failure;
- определить, существует ли конкретное нарушение;
- определить, должен ли finding быть создан;
- определить, требует ли файл ручной проверки;
- определить, присутствовало ли намеренное вмешательство;
- определить, является ли файл вредоносным.

Проект непосредственно решает первые четыре задачи. Последние две требуют
дополнительного ground truth и анализа semantics.

## Единица оценки

**Unit of evaluation**, или единица оценки, определяет, что считается одним
примером.

### File-level

Один PE-файл является одним примером.

Вопрос:

```text
должен ли файл получить хотя бы один finding
```

Преимущество — простая итоговая таблица. Недостаток — файл с одной
повреждённой entry и файл с тысячами повреждений учитываются одинаково.

### Record-level

Одна `RUNTIME_FUNCTION` или одна `UNWIND_INFO` является примером.

Вопрос:

```text
правильно ли отмечена конкретная запись
```

Это точнее для parser и per-record anomalies, но требует детальной разметки
каждой записи.

### Finding-level

Один потенциальный finding code для одного файла является примером.

Вопрос:

```text
должен ли code X присутствовать в отчёте файла Y
```

Так можно измерять precision и recall отдельно для каждого из 27 rules.

### Event-level

Одно динамическое событие является примером.

Вопрос:

```text
зарегистрирован ли фактический вызов или handler hit
```

Требуется внешний trace или специально контролируемый target.

## Ground truth

**Ground truth** — заранее установленная эталонная разметка, с которой
сравнивается результат инструмента.

Ground truth должен отвечать:

- какое нарушение присутствует;
- где оно находится;
- почему оно считается нарушением;
- каким способом это подтверждено;
- кто выполнил разметку;
- допускается ли неоднозначный verdict.

Источники ground truth:

1. специально сконструированный sample;
2. differential comparison с независимыми parsers;
3. compiler/linker provenance;
4. ручная экспертная проверка;
5. сравнение disk/memory/baseline versions;
6. instrumented dynamic target;
7. consensus нескольких экспертов.

Synthetic sample даёт точный ground truth по внесённому изменению, но плохо
представляет разнообразие реальных toolchains. Реальный corpus представляет
разнообразие, но требует дорогой разметки.

## Confusion matrix

Для бинарного решения используются четыре результата.

### True Positive, TP

Нарушение присутствует, и инструмент его обнаружил.

### False Positive, FP

Нарушение отсутствует, но инструмент создал положительный сигнал.

### True Negative, TN

Нарушение отсутствует, и инструмент не создал сигнал.

### False Negative, FN

Нарушение присутствует, но инструмент его не обнаружил.

Матрица:

| Ground truth | Сигнал есть | Сигнала нет |
|---|---:|---:|
| Нарушение есть | TP | FN |
| Нарушения нет | FP | TN |

Без размеченных positive examples нельзя вычислить TP и FN. Без размеченных
negative examples нельзя вычислить TN и FP.

## Accuracy

**Accuracy**, или доля правильных решений:

```text
accuracy = (TP + TN) / (TP + TN + FP + FN)
```

Accuracy сильно зависит от баланса classes.

Если в corpus 990 benign и 10 anomalous files, инструмент, всегда отвечающий
«аномалии нет», получит:

```text
accuracy = 990 / 1000 = 99%
```

но:

```text
recall = 0 / 10 = 0%
```

Поэтому overall accuracy не должна быть единственной метрикой triage tool.

## Sensitivity и recall

**Sensitivity**, также **recall** или true positive rate:

```text
recall = TP / (TP + FN)
```

Она отвечает:

```text
какую долю реально существующих нарушений обнаружил инструмент
```

Для проекта recall нужно измерять per finding class. Например, отдельный
recall для:

- `rf_overlaps`;
- `unwind_rva_oob`;
- `UA_BAD_OPCODE`;
- writable handler placement;
- runtime `RtlAddFunctionTable` registration.

Объединение всех нарушений в одну категорию скрывает слабые классы.

## Specificity

**Specificity**, или true negative rate:

```text
specificity = TN / (TN + FP)
```

Она отвечает:

```text
какую долю корректных объектов инструмент не пометил ошибочно
```

Для analyst-facing triage specificity важна, потому что false positives
создают ручную нагрузку.

## Precision

**Precision**, или positive predictive value:

```text
precision = TP / (TP + FP)
```

Она отвечает:

```text
какая доля созданных положительных сигналов подтверждается ground truth
```

Precision зависит от prevalence нарушений в corpus. Даже неизменный detector
может иметь разную precision в исследовательском наборе с 50% anomalies и в
реальном потоке с 0.1% anomalies.

## Negative Predictive Value

```text
NPV = TN / (TN + FN)
```

Показатель отвечает, насколько надёжен отрицательный результат в выбранном
corpus. Для проекта его нельзя интерпретировать как гарантию отсутствия
любого вмешательства, потому что проверяется ограниченное пространство
классов.

## F1

F1 является гармоническим средним precision и recall:

```text
F1 = 2 * precision * recall / (precision + recall)
```

F1 не использует TN и полезна при дисбалансе classes, но также скрывает
различие между precision и recall. Поэтому обе исходные метрики должны
публиковаться отдельно.

## False Positive Rate

```text
FPR = FP / (FP + TN) = 1 - specificity
```

Если specificity равна 99%, FPR равна 1%. Для потока из миллиона benign
файлов это теоретически до десяти тысяч сигналов при аналогичном
распределении. Абсолютная analyst workload зависит от объёма данных.

## False Negative Rate

```text
FNR = FN / (FN + TP) = 1 - recall
```

Этот показатель особенно важен для жёстких structural violations, где
ожидается почти детерминированное обнаружение при условии поддерживаемой
версии формата.

## Threshold

Проект имеет несколько thresholds:

- prevalence выше 1% для ряда integrity findings;
- anomaly prevalence выше 5%;
- reuse выше 10% или 30%;
- dominance выше 80%;
- score verdict thresholds 15, 40 и 70.

Изменение threshold меняет trade-off.

Снижение threshold:

- обычно увеличивает recall;
- обычно увеличивает false positives.

Повышение threshold:

- обычно увеличивает specificity;
- может увеличить false negatives.

Threshold нельзя выбирать только по synthetic samples, специально созданным
под существующие правила.

## ROC и PR curves

Если система выдаёт непрерывный score, можно изменять decision threshold и
строить curve.

**ROC curve** показывает:

```text
true positive rate против false positive rate
```

**PR curve** показывает:

```text
precision против recall
```

Для редких positive classes PR curve часто информативнее ROC, потому что
сильнее отражает влияние false positives.

Текущий score является суммой policy weights. Построение curve возможно
технически, но имеет смысл только на независимом размеченном corpus.

## Calibration

**Calibration** отвечает на вопрос, соответствует ли числовая оценка
эмпирической частоте события.

Если система заявляет вероятность 0.8 для ста cases, приблизительно 80 из них
должны подтверждаться при хорошей calibration.

Поле `suspicion = score / 100` не calibrated probability. Поэтому для него
нельзя применять вероятностную интерпретацию.

## Confidence interval

Результат sample является оценкой неизвестного свойства более широкой
совокупности.

Если в 106 benign files нет false positives:

```text
observed specificity = 106 / 106 = 100%
```

Это не доказывает universal specificity 100%. При простой биномиальной
модели двусторонний 95% Wilson interval имеет нижнюю границу приблизительно
96.5%.

Wilson interval для доли:

```text
center =
(p_hat + z^2/(2n)) / (1 + z^2/n)

half_width =
z / (1 + z^2/n)
* sqrt(p_hat(1-p_hat)/n + z^2/(4n^2))
```

где:

```text
p_hat = x / n
z = 1.96 для приблизительного 95% interval
```

Даже interval не исправляет corpus bias. Если все files получены от
ограниченного набора vendors и toolchains, математическая формула не делает
выборку репрезентативной автоматически.

## Independence assumption

Простая биномиальная модель предполагает независимые испытания.

106 files могут содержать:

- десятки DLL одной CPython distribution;
- несколько binaries одного compiler version;
- общие runtime libraries;
- похожие linker options.

Такие samples коррелированы. Эффективное количество независимых layouts
меньше числа файлов. Поэтому полезно группировать результаты по:

- vendor;
- product;
- compiler;
- linker;
- architecture feature;
- presence of handlers;
- number of runtime functions.

## Что доказывает corpus 106/106

Зафиксированный результат:

```text
106/106 valid reports
174 795 RUNTIME_FUNCTION
0 parse failures
0 structural unwind anomalies
0 nonzero heuristic scores
```

Он подтверждает:

1. совместимость parser с выбранным benign corpus;
2. отсутствие наблюдаемых false positives по правилу
   «ненулевой score/finding является положительным сигналом»;
3. способность обработать большое число реальных entries;
4. стабильность outputs на этих layouts.

Он не подтверждает:

- recall на реальных вмешательствах;
- поддержку всех Windows toolchains;
- поддержку V3;
- отсутствие false positives в мировой совокупности;
- общую accuracy.

## Что доказывают 6 regression samples

Два benign и четыре suspicious fixtures проверяют:

- ожидаемые paths parser;
- срабатывание конкретных известных rules;
- score/verdict contract;
- стабильность JSON.

Это **functional regression coverage**.

Оно не является оценкой external sensitivity, потому что suspicious samples
сконструированы под известные conditions. Инструмент фактически проверяется
на задачах, которые разработчик заранее вложил в fixtures.

## Что доказывают 1000 mutations

Результат:

```text
634 accepted valid reports
366 controlled rejections
0 crashes
0 hangs
0 invalid reports
```

подтверждает robustness относительно выполненных mutations:

- malformed inputs обрабатываются контролируемо;
- parser не упал;
- report contract сохранился.

Это не classification accuracy. Для большинства mutations неизвестно,
какой finding должен был быть истинным.

## Что доказывают 124/124 Windows reports

Результат означает, что все собранные reports прошли JSON Schema и
cross-field semantic validation.

Проверяется:

- структура report;
- согласованность counters;
- status fields;
- event bounds;
- metadata;
- отсутствие нарушений schema.

Это не означает, что все возможные dynamic paths были достигнуты.

## Что доказывают 4/4 focused smoke scenarios

Четыре purpose-built targets подтверждают работу selected mechanisms:

- VEH;
- VCH;
- UEF;
- runtime function-table registration.

Это проверка известных scenarios. Она не измеряет coverage реальных
программ, anti-debug behavior, multi-process logic и всех способов
регистрации.

## Parser accuracy и detector accuracy

Эти понятия необходимо разделять.

### Parser structural accuracy

Вопрос:

```text
правильно ли bytes преобразованы в поля и summaries
```

Методы:

- byte-level golden fixtures;
- differential comparison;
- round-trip там, где применимо;
- compiler-generated samples;
- boundary unit tests.

### Heuristic detection accuracy

Вопрос:

```text
правильно ли findings соответствуют размеченным аномалиям
```

Методы:

- per-class labeled corpus;
- precision/recall;
- threshold sweep;
- error analysis.

### Runtime observation accuracy

Вопрос:

```text
зарегистрировал ли collector фактически произошедшие события
```

Методы:

- instrumented target ground truth;
- independent debugger/ETW trace;
- timestamps and event identities;
- repeated runs.

Нельзя объединять эти три слоя в один процент.

## Строгий benchmark plan

### Шаг 1. Зафиксировать taxonomy

Для каждого из 27 findings определить:

- positive condition;
- negative condition;
- ambiguous/excluded condition;
- expected location;
- expected affected count.

### Шаг 2. Собрать corpus

Минимальные strata:

- MSVC разных versions;
- MinGW-w64;
- Clang/LLVM for Windows;
- system binaries;
- user applications;
- DLL, EXE и PYD;
- binaries с C, C++ EH и без handlers;
- packed/protected samples;
- handcrafted malformed samples;
- V1, V2 и V3 после реализации поддержки.

### Шаг 3. Разделить development и test

```text
development set -> выбор rules и thresholds
test set        -> однократная итоговая оценка
```

Использование test set для настройки превращает его в development set.

### Шаг 4. Выполнить независимую разметку

Желательно два эксперта. Расхождения фиксируются и разрешаются отдельно.
Нужно хранить rationale, а не только label.

### Шаг 5. Измерить per-class metrics

Для каждого finding:

- TP;
- FP;
- TN;
- FN;
- precision;
- recall;
- specificity;
- F1;
- confidence interval.

### Шаг 6. Проверить thresholds

Запустить score sweep и prevalence threshold variants. Выбирать policy по
заранее определённой цели, например:

```text
минимизировать false-positive burden
при recall жёстких structural violations не ниже заданного уровня
```

### Шаг 7. Провести error analysis

Каждый FP и FN должен получить:

- root cause;
- affected toolchain;
- решение: исправить, документировать или исключить;
- regression fixture, если исправление принято.

### Шаг 8. Опубликовать limitations

Benchmark должен указывать:

- даты;
- hashes;
- версии;
- состав corpus;
- exclusions;
- confidence intervals;
- known bias.

## Какая метрика главная для этого проекта

Одной главной метрики нет.

Для hard structural rules приоритет:

```text
высокий per-class recall
```

Для контекстных placement/reuse rules:

```text
высокая precision
и низкая analyst false-positive burden
```

Для benign compatibility:

```text
specificity
```

Для parser robustness:

```text
crash-free execution, controlled rejection, sanitizer/fuzz results
```

Для dynamic collector:

```text
event recall на instrumented targets
и корректность event semantics
```

## Технически корректный ответ о текущей точности

> Общая accuracy проекта пока не установлена, потому что нет достаточно
> большого независимого размеченного positive corpus для всех классов
> вмешательств. На выбранном benign corpus наблюдаемая file-level specificity
> составила 106/106, то есть 100%; нижняя граница простого 95% Wilson interval
> приблизительно 96.5%, но выборка ограничена. Шесть regression samples
> подтверждают ожидаемую функциональность известных rules, 1000 mutations —
> robustness, 124 Windows reports — корректность schema/semantics, а 4 smoke
> scenarios — работу выбранных dynamic mechanisms. Эти результаты нельзя
> складывать в один процент.

## Технические источники

1. NIST Static Analysis Tool Study Methodology — определения precision,
   accuracy и recall при сравнении analysis tools:
   `https://www.nist.gov/system/files/documents/2021/03/24/CAS%202012%20Static%20Analysis%20Tool%20Study%20Methodology.pdf`
2. NIST/SEMATECH e-Handbook of Statistical Methods — confidence intervals и
   основы статистической оценки:
   `https://www.itl.nist.gov/div898/handbook/`
3. Документация проекта:
   `docs/evidence_matrix.md`, `docs/threshold_calibration.md`,
   `docs/PRODUCT_READINESS.md`.

## Контрольные вопросы

1. Почему 106/106 не является общей accuracy?
2. Чем specificity отличается от precision?
3. Почему synthetic positive samples не дают внешнюю sensitivity?
4. Что измеряют mutations?
5. Зачем разделять file-level и finding-level metrics?
6. Почему один accuracy-процент опасен при class imbalance?
7. Что означает confidence interval?
8. Почему correlated binaries уменьшают effective sample diversity?
9. Как избежать leakage между development и test set?
10. Какие метрики нужны отдельно для parser, heuristics и dynamics?
