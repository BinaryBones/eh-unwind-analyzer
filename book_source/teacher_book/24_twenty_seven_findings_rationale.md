# Том III. Полная система 27 признаков: основания, связи и ручная проверка

## Что именно означает число 27

В текущей версии `heuristics.c` существует 27 возможных публичных finding
codes. Это не 27 полей PE и не 27 типов атак. Это 27 именованных результатов,
которые система может включить в массив:

```json
"findings": []
```

Один finding может агрегировать множество однотипных нарушений. Например,
`rf_oob` создаётся один раз, даже если за границы image выходят десять
`RUNTIME_FUNCTION`.

Число 27 получено декомпозицией технических слоёв:

```text
6  findings PE layout
7  findings RUNTIME_FUNCTION
2  findings UNWIND_INFO integrity
3  findings reuse и handler statistics
5  findings placement и permissions
4  combined findings
---
27 публичных finding codes
```

Внутри `unwind_anomalies` дополнительно различаются 12 причин `UA_*`.
Поэтому глубина проверки больше, чем простое число публичных кодов, но
выдавать их за 39 независимых признаков было бы неправильно.

## Критерии включения признака

Finding включён в текущую систему, если выполняются следующие условия.

1. Он проверяет отдельный технический инвариант или отдельный класс
   контекстной аномалии.
2. Его можно вычислить детерминированно.
3. Его можно локализовать или количественно измерить.
4. Для него существует понятный manual validation workflow.
5. Его можно закрепить unit или regression test.
6. Он не дублирует полностью другой finding.
7. Для него можно назвать границы и benign alternatives.

Эти критерии важнее самого количества.

## Группа I. Шесть признаков PE layout

### 1. `pe_section_raw_oob`

**Проверяемый объект.** Поля `PointerToRawData` и `SizeOfRawData` section
header.

**Инвариант.**

```text
PointerToRawData <= file_size
SizeOfRawData <= file_size - PointerToRawData
```

**Что означает нарушение.** Section объявляет байты, которых нет во входном
файле. Любая попытка читать полный raw range без bounds check вышла бы за
buffer.

**Почему признак важен для EH/unwind.** `.pdata` или `.xdata` может находиться
в такой section. Тогда RVA формально принадлежит image, но фактические байты
metadata отсутствуют.

**Вес и severity.**

```text
weight 25
severity high
family table_integrity
```

Высокий вес связан с прямым нарушением физической доступности данных.

**Benign alternatives.** Обрезанная передача, повреждение архива, неверный
dump memory image, нестандартный инструмент создания файла. Они объясняют
происхождение, но не делают диапазон безопасным.

**Ручная проверка.** Сравнить сумму полей с фактическим размером файла,
проверить overlay и определить, является ли объект обычным disk PE или
неполным memory dump.

**Что не обнаруживается.** Raw range может быть доступным, но содержать
семантически неверные данные.

### 2. `pe_section_virtual_oob`

**Проверяемый объект.** `VirtualAddress`, virtual span section и
`SizeOfImage`.

**Инвариант.**

```text
VirtualAddress + virtual_span <= SizeOfImage
```

Проект вычисляет virtual span с учётом `VirtualSize` и `SizeOfRawData`,
поскольку реальный mapping policy должен учитывать как объявленный размер в
памяти, так и доступный raw content.

**Что означает нарушение.** Section выходит за объявленную границу image.
RVA внутри её хвоста нельзя уверенно считать принадлежащим загружаемому
образу.

**Связь с EH/unwind.** `BeginAddress`, `EndAddress`, `UnwindInfoRVA` и
`HandlerRVA` являются image-relative. Ошибка `SizeOfImage` или section span
разрушает основу их проверки.

**Вес и severity.**

```text
weight 20
severity high
```

Вес немного ниже raw OOB, потому что фактическое loader behavior может
зависеть от дополнительных правил выравнивания, но модель image уже
несогласованна.

**Ручная проверка.** Сопоставить `SizeOfImage`, `SectionAlignment`, последний
section end и результат загрузки Windows loader в изолированной среде.

**Граница.** Признак не доказывает, что Windows обязательно загрузит файл или
откажет: analyzer проверяет собственный строгий parser contract.

### 3. `pe_section_raw_overlap`

**Проверяемый объект.** Пары raw ranges sections.

Для sections A и B:

```text
A = [A.raw_begin, A.raw_end)
B = [B.raw_begin, B.raw_end)
```

Overlap существует, если:

```text
A.raw_begin < B.raw_end
and
B.raw_begin < A.raw_end
```

**Что означает нарушение.** Одни байты файла одновременно объявлены частью
двух sections.

**Почему это важно.** Разные parser, loader и inspection tools могут
интерпретировать такие bytes по-разному. Атакующий может использовать
неоднозначность для parser differential.

**Вес и severity.**

```text
weight 15
severity medium
```

Overlap значим, но некоторые упаковщики и специально сформированные images
могут использовать нестандартные layouts.

**Ручная проверка.** Выписать обе пары raw boundaries, определить реальную
область пересечения и сравнить отображение в нескольких независимых tools.

**Граница.** Пересечение не доказывает, что именно EH metadata была
модифицирована.

### 4. `pe_section_virtual_overlap`

**Проверяемый объект.** Virtual ranges sections.

**Что означает нарушение.** Один RVA попадает более чем в одну section по
объявленным spans.

**Почему severity выше raw overlap.** EH/unwind адреса выражены в RVA. Если
RVA имеет две возможные section identities, неоднозначными становятся
permissions, имя section и mapping в file offset.

**Вес и severity.**

```text
weight 20
severity high
```

**Возможное вмешательство.** Handler может быть представлен одним parser как
исполняемый, а другим как неисполняемый; metadata может скрываться в
перекрывающихся mappings.

**Ручная проверка.** Построить отсортированный список virtual intervals,
определить все sections для спорного RVA и проверить фактическое memory map
после загрузки.

**Граница.** Проект сообщает структурную неоднозначность, но не моделирует
все частные loader decisions.

### 5. `pe_section_misaligned`

**Проверяемый объект.** Соответствие section fields объявленным
`FileAlignment` и `SectionAlignment`.

Типовые условия:

```text
PointerToRawData mod FileAlignment = 0
VirtualAddress mod SectionAlignment = 0
```

с учётом допустимых специальных случаев формата.

**Что означает нарушение.** Layout не соответствует собственной alignment
policy optional header.

**Почему признак medium.** Alignment errors могут появляться в custom,
handcrafted или very-small-alignment images. Не каждое отклонение приводит к
неправильному чтению EH metadata.

**Вес и severity.**

```text
weight 8
severity medium
```

**Ручная проверка.** Проверить значения alignments, кратность offsets,
специальные ограничения PE и фактическую загрузку.

**Граница.** Это общий PE signal. Он не является специфичным для `.pdata`.

### 6. `pe_exception_directory_oob`

**Проверяемый объект.** Data directory с индексом exception table.

**Инвариант.** Полный диапазон:

```text
[ExceptionRVA, ExceptionRVA + ExceptionSize)
```

должен принадлежать image и быть отображаемым в доступные file bytes для
статического разбора.

**Что означает нарушение.** Analyzer не может безопасно получить полный
массив `RUNTIME_FUNCTION`.

**Почему это прямой EH/unwind признак.** Это корневая directory, из которой
начинается весь статический pipeline.

**Вес и severity.**

```text
weight 25
severity high
```

**Ручная проверка.** Проверить directory entry, section mapping, кратность
размера 12 байтам и возможное усечение файла.

**Граница.** Пустая directory и directory OOB различаются. Пустота может быть
допустима для leaf-only image; OOB означает недоступный объявленный диапазон.

## Группа II. Семь признаков `RUNTIME_FUNCTION`

### 7. `no_runtime_functions`

**Условие.**

```text
runtime_function_count == 0
and image has executable content
```

Если executable sections отсутствуют, finding не создаётся.

**Почему отсутствие не всегда ошибка.** Leaf function, не изменяющая
nonvolatile state и не выделяющая stack frame, может раскручиваться без
function table entry. Теоретически небольшой image может состоять только из
таких функций.

**Почему сигнал всё же нужен.** Для крупного x64 image с вызовами, stack
allocations и nonleaf functions полное отсутствие `.pdata` требует
объяснения.

**Вес и severity.**

```text
weight 10
severity medium
```

**Ручная проверка.** Дизассемблировать executable sections, найти `call`,
изменения `RSP`, сохранения nonvolatile registers и определить, действительно
ли весь код leaf-only.

**Граница.** Проект пока не выполняет эту disassembly-проверку автоматически.

### 8. `invalid_ranges`

**Инвариант.**

```text
EndAddress > BeginAddress
```

**Что означает нарушение.** Диапазон пустой или направлен назад. Он не может
однозначно описывать непустой фрагмент кода.

**Threshold.**

```text
<= 1% affected: weight 10, medium
>  1% affected: weight 20, high
```

**Почему используется доля.** Одна повреждённая entry в таблице из десятков
тысяч отличается по масштабу от массового нарушения. При этом даже единичная
entry сохраняется как finding.

**Ручная проверка.** Найти entry по representative RVA, проверить endian
decode, соседние records и исходные 12 bytes.

**Возможное вмешательство.** Изменение `EndAddress` может скрывать часть
function coverage или ломать поиск текущего frame.

**Граница.** Корректный диапазон ещё не означает, что он совпадает с
фактической функцией.

### 9. `rf_oob`

**Инвариант.**

```text
BeginAddress < SizeOfImage
EndAddress <= SizeOfImage
```

Дополнительно диапазон должен соответствовать доступной executable области
при ручной интерпретации.

**Что означает нарушение.** Function entry описывает код вне объявленного
image.

**Threshold и веса.**

```text
<= 1%: +10, medium
>  1%: +25, high
```

**Почему высокий вариант имеет вес 25.** Массовые out-of-image ranges
разрушают function table как индекс текущего instruction pointer.

**Ручная проверка.** Проверить `SizeOfImage`, section ends, ASLR-independent
RVA и отсутствие ошибочного смешения RVA с VA.

**Граница.** Внутри image range может всё равно указывать на данные, а не на
код; это отдельный возможный будущий признак.

### 10. `unwind_rva_oob`

**Проверяемый объект.** Третье поле `RUNTIME_FUNCTION`.

**Инвариант.** `UnwindInfoRVA` должен указывать на доступную и достаточно
длинную запись внутри image/file mapping.

**Что означает нарушение.** Function range существует, но описание обратного
восстановления контекста отсутствует по указанному адресу.

**Threshold и веса.**

```text
<= 1%: +10, medium
>  1%: +25, high
```

**Почему это один из основных признаков вмешательства.** Изменение одного
32-bit RVA способно перенаправить decoder на чужие данные, вызвать
неправильный unwind или скрыть handler relation.

**Ручная проверка.** Выполнить `pe_rva_to_fileoff`, проверить section,
alignment и первые четыре header bytes.

**Граница.** Доступный RVA может вести к синтаксически корректной, но чужой
записи. Такой случай частично покрывается reuse/statistics, но требует
code-to-metadata correspondence.

### 11. `rf_unsorted`

**Нормативное ожидание.** Function table entries должны быть отсортированы по
`BeginAddress`.

**Как считается.** Во время исходного прохода проект фиксирует inversions:
следующий `BeginAddress` меньше предыдущего.

**Почему порядок важен.** Runtime lookup использует упорядоченную таблицу.
Нарушение может изменить результат поиска или сделать его
implementation-dependent.

**Вес и severity.**

```text
weight 15
severity medium
```

**Почему не high автоматически.** Analyzer может скопировать entries,
отсортировать их и продолжить проверку overlaps. Наличие inversion не всегда
означает повреждение самих ranges.

**Ручная проверка.** Сравнить исходный порядок `.pdata` с сортировкой,
проверить, является ли directory цельной таблицей или смешением данных.

**Граница.** Сортировка для анализа не исправляет input и не гарантирует
runtime acceptance.

### 12. `rf_overlaps`

**Проверяемый объект.** Отсортированные function intervals.

Для предыдущего максимального конца `max_end`:

```text
current.BeginAddress < max_end
```

означает overlap.

**Что означает нарушение.** Один instruction RVA покрывается несколькими
`RUNTIME_FUNCTION`.

**Почему это сильный сигнал.** Function table должна давать однозначную запись
для virtual unwind. Overlap нарушает однозначность выбора metadata.

**Вес и severity.**

```text
weight 25
severity high
```

**Ручная проверка.** Определить обе entries, проверить chained fragments и
убедиться, что overlap не является ошибкой собственного определения interval.

**Граница.** Раздельные noncontiguous fragments допустимы через chained info,
но они не должны произвольно перекрывать один instruction range.

### 13. `duplicate_begin`

**Условие.**

```text
entry[i].BeginAddress == entry[i-1].BeginAddress
```

после сортировки.

**Что означает нарушение.** Две entries претендуют на один начальный адрес.

**Отличие от overlap.** Duplicate begin является более конкретной формой
неоднозначности. Он может сопровождаться overlap, но сохраняется отдельно для
диагностики причины.

**Вес и severity.**

```text
weight 10
severity medium
```

**Почему вес не суммируется как два независимых доказательства.** Findings
могут иметь общую первопричину. Поэтому analyst должен смотреть на family и
raw entries, а не считать каждый code независимым экспериментом.

**Ручная проверка.** Сравнить `EndAddress` и `UnwindInfoRVA` обеих entries.

**Граница.** Finding не определяет, какая из дубликатных entries является
правильной.

## Группа III. Два признака `UNWIND_INFO` integrity

### 14. `unwind_parse_fail`

**Источник.** `unwind_parse` вернул `false` для одной или нескольких entries.

**Parse failure означает**, что decoder не смог безопасно завершить
структурное чтение. Причинами могут быть:

- неизвестная version;
- усечённый header;
- недостающий operand;
- невозможный tail;
- chain read failure;
- выход mapping за доступный buffer.

**Threshold и веса.**

```text
<= 1%: +10, medium
>  1%: +25, high
```

**Почему failure отделён от anomaly.** Некоторые anomalies можно отметить и
продолжить parsing. Failure означает, что итоговая `UnwindSummary` не может
считаться полностью полученной.

**Ручная проверка.** Использовать `parse_error`, исходный `UnwindInfoRVA`,
hex dump и официальное описание конкретной version.

**Критическая оговорка.** Корректная новая version, которую parser ещё не
поддерживает, также создаст parse failure. Это compatibility gap, а не
повреждение файла.

### 15. `unwind_anomalies`

**Источник.** `UnwindSummary.anomalies != 0`.

**Что агрегируется.** Двенадцать `UA_*` flags.

**Threshold.**

```text
<= 5% affected records: +10, medium
>  5% affected records: +20, high
```

**Почему threshold выше, чем для OOB.** Некоторые operand sanity и ordering
отклонения могут зависеть от редких compiler patterns. Для массового
нарушения вероятность системной проблемы выше.

**Почему один finding, а не двенадцать.** Несколько flags могут возникнуть из
одного повреждённого header. Отдельное начисление веса за каждый bit
искусственно увеличивало бы score.

**Ручная проверка.** Расшифровать short names из report:

```text
ver, trunc, op, arg, off, chain_loop, chain_depth,
handler_oob, order, operand_sanity, alignment, chain_invalid
```

и проверить конкретные bytes.

**Граница.** Finding сообщает структурную проблему metadata, но не
устанавливает её происхождение.

## Группа IV. Три статистических признака

### 16. `unwind_reuse_moderate`

**Метрика.**

```text
unwind_reuse_ratio =
max_count_for_one_UnwindInfoRVA / total_runtime_functions
```

**Candidate condition.**

```text
ratio > 0.10
total > 200
```

**Дополнительное условие.** Должен существовать другой static signal.
Умеренный reuse без corroboration подавляется.

**Вес и severity.**

```text
weight 10
severity medium
```

**Почему reuse может быть нормальным.** Одинаковые prologs, shared metadata,
compiler folding и runtime helpers могут законно уменьшать размер таблиц.

**Почему признак всё же полезен.** В сочетании с placement, integrity или
handler dominance reuse может указывать на централизованную схему
перенаправления.

**Ручная проверка.** Найти dominant `UnwindInfoRVA`, перечислить функции,
проверить одинаковы ли их реальные prologs и не используется ли chained info.

### 17. `unwind_reuse_strong`

**Условие.**

```text
ratio > 0.30
total > 200
```

**Вес и severity.**

```text
weight 20
severity high
```

**Почему нужен минимальный размер.** В таблице из трёх entries две одинаковые
дают 66.7%, но статистически это слабое основание. Условие `total > 200`
исключает такие малые samples.

**Почему threshold не является универсальной нормой.** Он является
консервативным engineering default и должен проверяться на расширенном corpus
разных toolchains.

**Ручная проверка.** Сравнить dominant record с распределением function sizes,
compiler/runtime identity и фактическими prologs.

**Граница.** Сильный reuse не доказывает обфускацию.

### 18. `handler_dominance`

**Метрика.**

```text
handler_reuse_ratio =
max_count_for_one_HandlerRVA / handler_count
```

**Candidate condition.**

```text
handler_count > 50
ratio > 0.80
```

**Контекстное подавление.** Если dominant handler находится в executable
code-like section и других static anomalies нет, finding не создаётся.

**Почему это необходимо.** `__C_specific_handler`,
`__CxxFrameHandler3/4` и другие runtime handlers могут законно обслуживать
множество функций.

**Вес и severity.**

```text
weight 15
severity medium
```

**Когда finding становится значимым.** При сочетании с writable/non-executable
placement, integrity errors или необычным reuse.

**Ручная проверка.** Идентифицировать handler, проверить imports/symbols,
section permissions, xrefs, language-specific data и runtime hits.

**Граница.** Статический dominant handler может никогда не исполняться на
исследованном path.

## Группа V. Пять placement-признаков

### 19. `unwind_in_exec_section`

**Условие.** Section, содержащая `UnwindInfoRVA`, имеет
`IMAGE_SCN_MEM_EXECUTE`.

**Ожидаемая модель.** Unwind metadata является данными и обычно размещается в
read-only `.xdata`, `.rdata` или related section.

**Почему executable placement подозрителен.** Bytes могут одновременно
интерпретироваться как code и metadata; это повышает риск parser
differential, сокрытия и self-referential layouts.

**Вес и severity.**

```text
weight 20
severity high
```

**Ручная проверка.** Проверить section flags, дизассемблирует ли инструмент
эту область как code, есть ли control-flow edges внутрь metadata.

**Граница.** Нестандартный linker может объединить code и read-only data.
Finding требует объяснения, но не является доказательством атаки.

### 20. `unwind_unusual_section`

**Условие.** Section name не относится к разрешённым xdata/rdata/pdata-like
именам и не распознаётся как plausibly unwind-named.

**Threshold.**

```text
count <= total / 20: +8, medium
count >  total / 20: +15, high
```

**Почему имя является слабым источником.** PE section name не определяет
семантику и может быть произвольным. Поэтому permissions сильнее имени.

**Зачем правило существует.** Необычное размещение помогает analyst быстро
найти custom linker/protector regions и сопоставить их с другими signals.

**Weakening.** Placement-only и single-family penalties могут снизить
confidence.

**Ручная проверка.** Проверить characteristics, entropy, соседние data,
compiler identity и mapping всех affected records.

**Implementation nuance.** При `total < 20` integer division даёт
`total / 20 == 0`, поэтому любое положительное count попадает в high branch.
Это кандидат для будущей calibration.

### 21. `unwind_writable_section`

**Условие.** Section с `UNWIND_INFO` имеет `IMAGE_SCN_MEM_WRITE`.

**Почему это сильнее необычного имени.** Writable permission является
функциональным свойством memory mapping. После загрузки metadata потенциально
может изменяться без изменения disk file.

**Threshold и веса.**

```text
до 5%: +10, medium
более 5%: +18, high
```

**Возможные benign причины.** JIT infrastructure, custom runtime,
post-load fixups, объединённая data section.

**Ручная проверка.** Определить, изменяются ли bytes во время исполнения;
сравнить disk и memory copies; проверить calls к APIs управления memory
protection.

**Граница.** Сам permission не доказывает фактическую модификацию.

### 22. `handler_nonexec_section`

**Условие.** `HandlerRVA` не принадлежит известной executable section.

**Почему это сильный structural signal.** Handler должен быть передан
управлению как код. Target в non-executable data противоречит обычной модели
исполнения.

**Вес и severity.**

```text
weight 15
severity high
```

**Возможные объяснения.** Неверный RVA, повреждённая metadata, section table
anomaly, runtime protection transition, custom loader.

**Ручная проверка.** Проверить mapping после загрузки, DEP permissions,
возможное изменение protection и фактическое значение handler в memory.

**Граница.** Static section flags не всегда равны текущим page protections
после `VirtualProtect`.

### 23. `handler_writable_section`

**Условие.** Handler target находится в section с write permission.

**Почему это важно.** Writable executable code облегчает runtime modification
и затрудняет утверждение, что disk bytes равны исполнявшимся bytes.

**Вес и severity.**

```text
weight 10
severity medium
```

**Почему не high автоматически.** Некоторые runtime-generated или unpacked
regions законно проходят состояние writable+executable.

**Ручная проверка.** Проверить W^X policy, фактические page protections,
изменения bytes и момент установки handler.

**Граница.** Section-level permission грубее page-level runtime protection.

## Группа VI. Четыре combined findings

### 24. `placement_exec_nonexec_handler_combo`

**Условие.**

```text
unwind_in_exec_section exists
and handler_nonexec_section exists
```

**Логика.** Metadata размещена там, где ожидается code, а handler указывает
туда, где code не ожидается. Два направления нарушения усиливают друг друга.

**Вес и severity.**

```text
weight 10
severity high
```

**Почему это отдельный finding.** Он выражает не новую raw observation, а
policy о значимости совместного появления.

**Ручная проверка.** Проверить обе стороны по конкретным RVA и исключить
ошибку section mapping.

### 25. `placement_integrity_combo`

**Условие.**

```text
(unwind in executable section or handler non-executable)
and
(parse failure or unwind anomaly or unwind RVA OOB)
```

**Логика.** Необычное размещение подкреплено повреждением содержимого или
указателя.

**Вес и severity.**

```text
weight 8
severity medium
family unwind_integrity
```

**Почему вес умеренный.** Исходные findings уже внесли основной вклад.
Combo добавляет ограниченный corroboration bonus.

**Граница.** Сигналы могут иметь одну первопричину, поэтому их нельзя
интерпретировать как независимые вероятности.

### 26. `reuse_dominance_combo`

**Условие.**

```text
unwind_reuse_ratio > 0.10
and handler_dominance finding exists
```

**Логика.** Централизация происходит одновременно на уровне unwind records и
handler targets.

**Вес и severity.**

```text
weight 8
severity medium
```

**Возможная benign причина.** Общий language runtime handler плюс
compiler-generated shared unwind descriptions.

**Ручная проверка.** Проверить, соответствует ли dominant handler известному
runtime и согласованы ли реальные prologs с общей metadata.

### 27. `writable_metadata_handler_combo`

**Условие.**

```text
unwind_writable_section exists
and handler_writable_section exists
```

**Логика.** И описание unwind, и код handler находятся в изменяемых regions.
Это создаёт возможность согласованного runtime изменения обеих сторон.

**Вес и severity.**

```text
weight 10
severity high
```

**Ручная проверка.** Снять memory snapshots до и после инициализации,
сравнить bytes, page protections и события регистрации.

**Граница.** Permission создаёт возможность изменения, но не доказывает, что
изменение состоялось.

## Почему отдельных findings не больше

Проект не создаёт отдельные публичные codes для каждого:

- `UWOP`;
- register number;
- `UA_*` bit;
- section name;
- dynamic exception code.

Причина — контроль гранулярности. Слишком мелкие findings:

- многократно оценивают одну первопричину;
- переполняют report;
- затрудняют сравнение файлов;
- делают score зависимым от случайного количества вторичных симптомов.

Низкоуровневые детали сохраняются в `UnwindSummary`, counters, operations
text и event timeline.

## Почему отдельных findings не меньше

Объединение всех ошибок в один code `malformed_unwind` потеряло бы:

- слой возникновения;
- severity;
- локализацию;
- manual workflow;
- возможность threshold calibration;
- проверяемость regression tests.

Разделение на 27 codes сохраняет техническую причину результата.

## Матрица покрытия классов вмешательств

| Класс изменения | Основные findings | Что подтверждается |
|---|---|---|
| Усечение или ложные file ranges | `pe_section_raw_oob`, `pe_exception_directory_oob` | Объявленные bytes недоступны |
| Ложный virtual layout | `pe_section_virtual_oob`, overlaps, misalignment | Image model неоднозначна или несогласованна |
| Подмена function boundaries | `invalid_ranges`, `rf_oob`, `rf_unsorted`, `rf_overlaps`, `duplicate_begin` | Function table нарушает structural contract |
| Подмена unwind pointer | `unwind_rva_oob`, `unwind_parse_fail` | Запись недоступна или не разбирается |
| Повреждение unwind encoding | `unwind_anomalies` | Нарушены version-specific rules |
| Перемещение metadata | три unwind placement findings | Section context необычен |
| Перенаправление handler | два handler placement findings | Target section не соответствует обычному коду |
| Централизация | reuse и dominance | Распределение ссылок необычно |
| Сочетание независимых слоёв | четыре combo findings | Несколько свойств взаимно подкрепляются |

## Какие вмешательства 27 признаков не гарантируют обнаружить

1. Изменение машинного кода при полностью согласованной metadata.
2. Замена handler на другой допустимый executable RVA.
3. Подмена semantics внутри существующего handler без изменения placement.
4. Runtime modification после окончания observation window.
5. Динамическая регистрация через ненаблюдаемый механизм.
6. Неисполненный path.
7. Корректная новая версия metadata без поддержки parser.
8. Изменение language-specific handler data, которое не нарушает текущие
   structural checks.
9. Подмена файла на другой валидный файл без trusted baseline.

## Как добавить новый признак правильно

Новый finding должен пройти последовательность.

1. Сформулировать технический инвариант или статистическую гипотезу.
2. Определить raw observations.
3. Назвать benign alternatives.
4. Выбрать family.
5. Обосновать severity и вес относительно существующих rules.
6. Добавить representative location и affected count.
7. Добавить unit test positive.
8. Добавить unit test benign suppression.
9. Проверить влияние на corpus и thresholds.
10. Обновить schema semantics, evidence matrix и учебный курс.

## Итоговое обоснование числа 27

Технически корректный ответ:

> В проекте 27 публичных finding codes, потому что текущая модель
> декомпозирована на 6 проверок PE layout, 7 проверок function table, 2
> агрегированных проверки `UNWIND_INFO`, 3 статистических pattern, 5
> placement-проверок и 4 combined rules. Число не объявляется полным числом
> возможных атак. Полнота оценивается по покрываемым классам вмешательств,
> traceability и тестам каждого правила. Внутри unwind decoder дополнительно
> различаются 12 диагностических причин `UA_*`.

## Контрольные вопросы

1. Почему `duplicate_begin` и `rf_overlaps` сохраняются отдельно?
2. Почему moderate reuse требует corroboration?
3. Почему handler dominance подавляется для обычного runtime handler?
4. Почему section name слабее section permission?
5. Почему `unwind_parse_fail` и `unwind_anomalies` разделены?
6. Почему combo finding может добавлять вес, хотя raw observations уже
   учтены?
7. Какие признаки являются жёсткими structural violations?
8. Какие признаки являются контекстными?
9. Какие признаки являются статистическими?
10. Как доказать, что новый finding не дублирует существующий?
