# Том II. Глава 7. `dynamic_win.c`: Windows dynamic evidence collector

## Назначение и граница платформы

Статическая часть проекта компилируется и работает на macOS, Linux и Windows, потому что читает PE как массив bytes. Динамическая часть использует Windows Debug API и должна исполнять Windows x64 target. Поэтому она доступна только в Windows build.

Это различие реализовано compile-time branch:

```c
#ifdef _WIN32
    /* реальный collector */
#else
    /* unsupported-platform stub */
#endif
```

На non-Windows система не пытается эмулировать process execution. `dynamic_collect_windows` инициализирует report, записывает понятную ошибку и возвращает false.

Следовательно:

```text
Linux/macOS host:
  static analysis Windows PE32+ AMD64 = поддерживается
  dynamic Windows exception validation = не поддерживается

Windows x64 host:
  static analysis = поддерживается
  dynamic validation = поддерживается
```

Wine или virtual machine могут быть отдельной средой исследования, но текущий код напрямую не реализует и не тестирует Wine-specific backend.

## Defensive intent

Header `dynamic.h` определяет цель как сбор runtime evidence:

- hits handlers из `UNWIND_INFO`;
- registration и hits VEH/VCH/UEF;
- registration dynamic function tables;
- first-chance и second-chance exception flow.

Collector не заявляет обход защит, извлечение скрытых данных или автоматическую деобфускацию. Он является ограниченным debugger, созданным под конкретные event types.

## Модель результата

`DynamicReport` хранит session state, counters, bounded events, bounded trace и human-readable log.

Состояние:

```c
bool enabled;
bool ran;
bool ok;
bool timed_out;
bool target_exited;
uint32_t target_exit_code;
```

`enabled` означает, что dynamic mode был запрошен и report инициализирован.

`ran` означает, что `CreateProcessA` succeeded и target действительно был создан.

`ok` означает:

```text
CREATE_PROCESS event был получен
&& debug loop не встретил internal failure
&& timeout не наступил
```

`target_exited` отдельно показывает normal observation `EXIT_PROCESS_DEBUG_EVENT`. Session может быть завершена принудительно по timeout, тогда target не считается self-exited.

Events ограничены:

```text
DYNAMIC_MAX_EVENTS = 256
```

После заполнения array новые события не перезаписывают старые; увеличивается `dropped_events`.

Trace также ограничен 256 instruction pointers. Input `trace_steps` clamp до 256.

## Module map

Breakpoints на system APIs нельзя ставить по address, полученному в process анализатора. Из-за ASLR module bases отличаются.

`ModList` содержит максимум 128 modules:

```c
typedef struct ModList {
    ModInfo mods[128];
    size_t count;
} ModList;
```

`mods_refresh_toolhelp`:

1. сбрасывает count;
2. вызывает `CreateToolhelp32Snapshot`;
3. перечисляет `MODULEENTRY32`;
4. сохраняет basename, base и size;
5. приводит name к lowercase.

Module list fixed-size. Если target загрузил более 128 modules, остаток не сохраняется. Truncation flag отсутствует. Это residual limit: API resolution для позднего module может не сработать без явной ошибки.

## Разрешение forwarded API

Windows export может быть forwarded. Например, symbol запрашивается через `kernel32.dll`, но фактический code address принадлежит `kernelbase.dll`.

`local_proc_loc` выполняет:

1. `GetModuleHandleA(preferred_mod)`;
2. `GetProcAddress(symbol)`;
3. `GetModuleHandleExA(...FROM_ADDRESS...)`, чтобы определить real local module;
4. получает basename real module;
5. вычисляет offset:

```text
offset = LocalFunctionVA - LocalRealModuleBase
```

После этого `add_api_bps_if_ready` ищет module с таким basename в target:

```text
TargetFunctionVA = TargetModuleBase + offset
```

Эта схема корректно переносит symbol location между процессами при одинаковой версии загруженного module. Она предполагает, что local и target используют совместимый module binary с тем же internal offset. Для обычного запуска на одной Windows installation это разумно; cross-architecture или module substitution потребовали бы remote export parsing.

## Наблюдаемые API

Collector ставит breakpoints на:

```text
AddVectoredExceptionHandler
AddVectoredContinueHandler
SetUnhandledExceptionFilter
RtlAddFunctionTable
RtlInstallFunctionTableCallback
```

Kinds хранятся как bit mask. Один address может соответствовать нескольким logical kinds, поэтому existing breakpoint получает:

```c
ex->kinds |= kind;
```

Это предотвращает дублирование `INT3` по одному address.

## Breakpoint model

```c
typedef struct Breakpoint {
    uint64_t addr;
    uint8_t orig;
    bool armed;
    bool rearm_pending;
    uint32_t kinds;
} Breakpoint;
```

`addr` — target VA.

`orig` — исходный byte, который был заменён.

`armed` — по address ожидается `0xCC`.

`rearm_pending` — исходная instruction временно восстановлена, breakpoint должен быть поставлен снова после single-step.

`kinds` — logical meanings address.

List имеет capacity 512. При переполнении `bp_add_and_arm` возвращает false, но dedicated overflow counter отсутствует.

## Запись bytes в remote process

`write_one_byte` сначала вызывает `WriteProcessMemory`. Если write failed, code сохраняет error и пробует временно изменить page protection:

```text
VirtualProtectEx(..., PAGE_EXECUTE_READWRITE)
WriteProcessMemory
VirtualProtectEx(..., oldProt)
```

После successful write вызывается `FlushInstructionCache`.

Причина cache flush: processor может иметь ранее полученные instruction bytes. После изменения executable memory debugger должен обеспечить согласованность instruction fetch.

Временный `PAGE_EXECUTE_READWRITE` расширяет permissions целевой страницы. Проект возвращает previous protection, но на короткий период изменяет security state target. Это unavoidable вмешательство выбранной software-breakpoint technique и должно учитываться при anti-debug-sensitive samples.

## Установка breakpoint

`bp_set`:

1. читает один byte по `addr`;
2. сохраняет его в `orig`;
3. пишет `0xCC`;
4. устанавливает `armed = true`;
5. очищает `rearm_pending`.

Здесь имеется subtle risk при повторной постановке: `bp_set` каждый раз заново читает current byte и записывает его в `orig`. Correct flow вызывает re-arm после того, как original instruction уже восстановлена, поэтому сохраняется правильный byte. Если функцию ошибочно вызвать на уже armed breakpoint, `orig` мог бы стать `0xCC`; guard в `bp_add_and_arm` предотвращает этот path.

`bp_clear` восстанавливает `orig` только если `armed`.

## Self-check

`bp_add_and_arm_selfcheck` после первой попытки установки снова читает byte и добавляет deterministic log line:

```text
[SelfCheck] ... OK (byte=0xcc)
```

Если byte не `0xCC`, появляется warning. Self-check также форматирует address как:

```text
module.dll+offset (absolute VA)
```

Это улучшает auditability: report показывает не только желание поставить breakpoint, но и результат remote memory verification.

Self-check log не является structured event. Он находится в `DynamicReport.details`, поэтому backend должен сохранять это поле, если требуется полный audit.

## Per-thread pending re-arm

После hit breakpoint временно снимается. Original instruction должна выполниться в том же потоке, который hit breakpoint. После single-step этот конкретный breakpoint ставится обратно.

`PendingRearmList` имеет 64 slots:

```c
typedef struct PendingRearmEntry {
    DWORD tid;
    Breakpoint* bp;
} PendingRearmEntry;
```

`pending_rearm_set` сначала обновляет existing entry для `tid`, затем ищет free slot. Если 64 threads одновременно находятся между breakpoint hit и single-step, insertion fails и session считается failed.

Один thread может иметь только один pending breakpoint. Это соответствует normal sequence: thread stopped on one breakpoint cannot hit another до выполнения original instruction и single-step.

При `EXIT_THREAD_DEBUG_EVENT` pending breakpoint также re-arm, чтобы завершение потока не оставило shared code без breakpoint.

## Командная строка target

Windows `CreateProcessA` принимает mutable command-line string, а не готовый `argv[]`. Поэтому collector строит строку по Microsoft C runtime quoting rules.

`append_cmd_arg`:

- добавляет quotes для empty string, spaces, tabs или internal quotes;
- удваивает backslashes перед quote;
- удваивает trailing backslashes перед closing quote.

Это существенно. Простое соединение arguments через spaces изменило бы boundaries. Например path с пробелом стал бы несколькими arguments.

CLI отделяет target arguments после `--`:

```text
eh_unwind_analyzer target.exe --dynamic -- --input sample.dat
```

Collector получает `child_argv` и сохраняет boundaries при построении Windows command line.

Report metadata по умолчанию redacts child arguments, потому что они могут содержать secrets. Это относится к `main.c`; actual CreateProcess command line всё равно включает переданные target arguments.

## Создание процесса

Используется:

```c
CreateProcessA(
    NULL,
    cmd.s,
    NULL,
    NULL,
    FALSE,
    DEBUG_ONLY_THIS_PROCESS,
    NULL,
    NULL,
    &si,
    &pi
)
```

`DEBUG_ONLY_THIS_PROCESS` означает, что дочерние процессы target автоматически не становятся debuggees этого collector.

Code намеренно не использует `CREATE_SUSPENDED`. Комментарий фиксирует обнаруженную практическую проблему: на некоторых configurations suspended debuggee не выдавал ожидаемый create event, что создавало deadlock. Debug API сам предоставляет ранний `CREATE_PROCESS_DEBUG_EVENT` до обычного user-mode execution.

После success:

```text
out->ran = true
hProcess = pi.hProcess
pid = pi.dwProcessId
```

## Static handler addresses как input dynamics

До debug loop collector строит unique list `handler_rvas` из успешно parsed records с `has_handler`.

List выделяется размером `rf_count`, минимум один element. Unique check линейный:

```text
для каждого handler
  сравнить со всеми уже сохранёнными
```

Worst-case complexity `O(n²)`. Для типичных handler counts это приемлемо, но большое PE с unique handler для каждого record может замедлить preparation. Hash set был бы масштабируемее.

На `CREATE_PROCESS_DEBUG_EVENT`:

```text
HandlerVA = base_main + HandlerRVA
```

и ставится `BP_UNWIND_HANDLER`.

Если RVA invalid, write may fail; failure считается best effort и не завершает session.

## Debug loop и timeout

Start time:

```c
uint64_t start = GetTickCount64();
```

На каждой iteration:

```text
elapsed = current - start
if elapsed > timeout_ms -> timeout
```

Сравнение строго `>`. Timeout event добавляется в structured events с `arg0 = timeout_ms`.

`WaitForDebugEvent` вызывается с 100 ms. `ERROR_SEM_TIMEOUT` означает отсутствие event в интервале и приводит к следующей iteration. Другой error завершает loop как failure.

Granularity timeout поэтому примерно 100 ms плюс время обработки события.

## Continuation status

Для каждого event initial:

```c
DWORD cont = DBG_CONTINUE;
```

Для ordinary exception, не принадлежащего breakpoint machinery:

```c
cont = DBG_EXCEPTION_NOT_HANDLED;
```

Это передаёт исключение обычному target dispatch.

Для собственных breakpoint и single-step:

```c
cont = DBG_CONTINUE;
```

потому что debugger полностью обработал служебное exception.

Неверный status здесь способен либо поглотить target exception, либо передать приложению `INT3`, вставленный analyzer.

## `CREATE_PROCESS_DEBUG_EVENT`

Collector:

1. устанавливает `got_create = true`;
2. сохраняет `base_main = lpBaseOfImage`;
3. refresh modules;
4. пытается поставить API breakpoints;
5. ставит breakpoints на static handler RVA;
6. закрывает `hFile` из event.

Закрытие file handle обязательно по Windows Debug API contract.

`base_main` — actual base. Он используется для статических handler RVA и address-to-section formatting.

## `LOAD_DLL_DEBUG_EVENT`

При каждой DLL load:

1. refresh module list;
2. повторно вызвать `add_api_bps_if_ready`;
3. закрыть `hFile`.

Повторная попытка нужна, потому что real module API мог отсутствовать раньше. Existing breakpoints deduplicate по address.

`UNLOAD_DLL_DEBUG_EVENT` только refresh list. Breakpoints внутри выгруженного module не удаляются из `BpList`. Их remote pages уже могут быть unmapped. На final cleanup `bp_clear` best-effort игнорирует failure. Если module выгружен и затем другой module загружен по тому же address, stale breakpoint model может стать проблемой. Это limitation текущего collector.

## Ordinary exception event

Для code, отличного от breakpoint и single-step:

```text
exceptions_seen++
first_chance_seen++ или second_chance_seen++
```

В event сохраняются:

- type `exception`;
- thread ID;
- exception address;
- exception code;
- first_chance flag;
- module by address.

После этого `DBG_EXCEPTION_NOT_HANDLED`.

Collector не сериализует `NumberParameters` и `ExceptionInformation[]`. Для access violation поэтому не сохраняются attempted address и operation type. Это направление расширения evidence model.

## Initial system breakpoint

После создания debuggee Windows генерирует initial breakpoint. Он не принадлежит `BpList`.

Code допускает один неизвестный breakpoint как initial:

```text
if !bp && !initial_break_ignored:
    initial_break_ignored = true
    DBG_CONTINUE
```

Следующие unknown breakpoints передаются как not handled.

Это pragmatic rule. Target может выполнить собственный early `INT3` до system breakpoint order, а system behavior может отличаться. Более строгая identification могла бы учитывать module/address и event sequence.

## Hit собственного `INT3`

По exception address выполняется `bps_find`.

Если breakpoint найден:

1. `bp_clear` восстанавливает original byte;
2. `rearm_pending = true`;
3. `pending_rearm_set(tid, bp)`;
4. открывается event thread;
5. читается context;
6. `ctx.Rip = addr`;
7. `ctx.EFlags |= 0x100`;
8. анализируются kinds;
9. записывается context;
10. event продолжается.

Комментарий «RIP points to INT3+1; rewind» реализуется присваиванием address exception. Поскольку `addr` равен адресу breakpoint, это возвращает execution на original instruction.

Если clear, pending storage, thread open, context read или context write fails, debug loop помечается failed и завершается после продолжения текущего event.

## Capture регистрации VEH

На entry `AddVectoredExceptionHandler` Windows x64 ABI:

```text
RCX = First
RDX = Handler
```

Collector:

```text
veh_registrations++
event type = veh_registration
arg0 = First
arg1 = Handler
```

Если Handler nonzero, ставится breakpoint `BP_CUSTOM_VEH_HANDLER`.

Collector не наблюдает return value API, поэтому не знает, была ли регистрация successful. Он фиксирует вызов и arguments. Чтобы подтвердить success, нужен return breakpoint или анализ последующего hit.

## Capture VCH

Аналогично:

```text
RCX = First
RDX = Handler
```

Counters и event types отделены:

```text
vch_registrations
vch_registration
BP_CUSTOM_VCH_HANDLER
vch_hits
```

Это сохраняет различие VEH и VCH phases.

## Capture UEF

На entry `SetUnhandledExceptionFilter`:

```text
RCX = Handler
```

Collector увеличивает `uef_set_calls`, создаёт `uef_registration` и ставит breakpoint на nonzero handler.

Как и для VEH, return value предыдущего filter не записывается.

Microsoft указывает, что top-level filter вызывается, когда exception достигает unhandled filter и process не debugged. Наличие active debugger может менять UEF behavior. Поэтому hit UEF под debugger нельзя считать гарантированным для всех scenarios; bundled smoke target и validation должны учитывать actual Windows semantics.

## Capture `RtlAddFunctionTable`

Arguments:

```text
RCX = FunctionTable
RDX = EntryCount
R8  = BaseAddress
```

Structured event:

```text
type = rtl_add_function_table
arg0 = table pointer
arg1 = count
arg2 = base
```

Collector не читает remote entries. Для полноценного dynamic table analysis нужно:

1. validate count upper bound;
2. compute byte size safely;
3. read remote array;
4. validate `RUNTIME_FUNCTION`;
5. resolve unwind records against supplied base;
6. snapshot page protections;
7. account for table lifetime and `RtlDeleteFunctionTable`.

Текущая реализация подтверждает API call, но не content.

## Capture callback table

`RtlInstallFunctionTableCallback`:

```text
RCX = TableIdentifier
RDX = BaseAddress
R8  = Length
R9  = Callback
```

Event stores all four arguments. Callback table is more dynamic: system may call supplied callback to obtain entries on demand. Full analysis потребовал бы breakpoint on callback и decoding return behavior.

## Handler hits

Kinds:

```text
BP_UNWIND_HANDLER
BP_CUSTOM_VEH_HANDLER
BP_CUSTOM_VCH_HANDLER
BP_CUSTOM_UEF
```

При hit соответствующий counter увеличивается и создаётся event:

```text
unwind_handler_hit
veh_handler_hit
vch_handler_hit
uef_handler_hit
```

Для static unwind handler address formatter показывает absolute VA, RVA и section.

Если `trace_steps > 0` и трасса ещё не собиралась, включается single-step trace:

```text
tracing = true
trace_tid = current tid
add_trace(current RIP)
trace_left = min(trace_steps, 256) - 1
```

После rewind `current RIP` равен handler entry. Поэтому первым trace element является address original handler instruction до её исполнения.

Трасса запускается только при первом handler hit. Последующие попадания продолжают
учитываться отдельными counters и events, но не накапливают новую RIP trace поверх
первой. Благодаря этому `trace_count` никогда не превышает заданный `trace_steps`.

## `EXCEPTION_SINGLE_STEP`

Сначала:

```text
pr_bp = pending_rearm_take(tid)
bp_set(pr_bp)
```

Это возвращает `0xCC` после выполнения original instruction.

Затем читается context.

Если active tracing принадлежит тому же thread:

```text
add_trace(ctx.Rip)
trace_left--
TF remains set
```

Когда `trace_left == 0`, TF снимается.

Если tracing не active для этого thread, TF снимается сразу.

`trace_count` включает initial handler RIP в общий бюджет. При `trace_steps = 32`
сохраняется не более 32 addresses: entry point и до 31 последующего single-step
addresses.

Collector поддерживает только один active trace session global to report.
Повторный handler hit не перезапускает и не перезаписывает трассу, потому что
`start_trace` возвращается при `trace_count != 0`. Counters и events повторных
hits продолжают записываться. Отдельные одновременные per-thread traces не
поддерживаются.

## Thread exit

Если thread завершился с pending re-arm, collector повторно ставит breakpoint. Это важно, потому что code memory принадлежит процессу, а не thread.

Если exiting thread был traced, trace state сбрасывается.

## Process exit

На `EXIT_PROCESS_DEBUG_EVENT`:

```text
process_exited = true
target_exited = true
target_exit_code = event code
```

Добавляется `process_exit` event с exit code в `arg0`. Loop завершится только после `ContinueDebugEvent`, что соответствует Debug API lifecycle.

Exit code zero не означает отсутствие anomalies. Это только status target process.

## Session finalization

После loop:

```text
timed_out = local timed_out
target_exited = process_exited
ok = got_create && debug_loop_ok && !timed_out
```

Затем collector пытается снять все breakpoints.

Если target сам не завершился, вызывается `TerminateProcess`. После этого collector
до одной секунды принимает и продолжает завершающие debug events, включая
`EXIT_PROCESS_DEBUG_EVENT`. Такой drain не добавляет фиксированные пять секунд к
каждому timeout-case и корректно завершает debug lifecycle.

Закрываются initial thread и process handles, освобождается handler list и command-line buffer.

Если `ok == false`, функция добавляет одну из summary errors:

- timeout;
- failure до create event;
- failure внутри event loop.

Даже при false `DynamicReport` остаётся доступным. `main.c` передаёт его в JSON/HTML, чтобы partial events и failure state не терялись.

## Semantics dynamic signal count

Report layer считает не raw events, а категории:

```text
1: any unwind handler hits
1: any VEH registration or hit
1: any VCH registration or hit
1: any UEF set or hit
1: any dynamic function table API call
1: any second-chance exception
```

Maximum category count шесть. Десять VEH hits всё равно дают один dynamic signal category.

Это summary diversity, а не event volume.

## Runtime evidence level

Strong runtime component:

```text
any handler hit
```

Medium components:

```text
dynamic table registration
second chance
```

Weak components:

```text
handler registrations
first chance
```

Result:

```text
strong, если strong>=1 и medium>=1
medium, если strong>=1 или medium>=2
weak, если medium>=1 или weak>=1
none иначе
```

Опять же это engineering taxonomy, не probability.

## Structured event limitations

`DynamicEvent` содержит generic `arg0..arg3`. Их meaning зависит от `type`.

Плюс: model compact и позволяет serializing разные APIs.

Минус: schema не выражает types напрямую. Backend должен знать mapping:

```text
veh_registration:
  arg0 First
  arg1 Handler

rtl_add_function_table:
  arg0 Table
  arg1 EntryCount
  arg2 BaseAddress
```

Для долгосрочной API лучше использовать typed subobjects или event-specific fields, сохранив backward-compatible base.

## Safety and trust boundary

Target является untrusted executable. Dynamic mode действительно запускает его. Он может:

- читать и изменять доступные user files;
- обращаться к сети;
- создавать child processes;
- обнаруживать debugger;
- зависать;
- потреблять ресурсы;
- атаковать parser/debugger through event volume.

`DEBUG_ONLY_THIS_PROCESS` не sandbox. Timeout не sandbox. Поэтому production deployment должен запускать dynamic worker в disposable Windows VM или hardened sandbox с resource limits и restricted network.

Backend нельзя запускать collector от имени privileged service account над arbitrary upload.

## Bundled dynamic smoke targets

Project содержит Windows test programs:

```text
dyn_veh.c
dyn_vch.c
dyn_uef.c
dyn_rtl_ftable.c
```

Они компилируются в:

```text
15_dynamic_veh.exe
16_dynamic_vch.exe
17_dynamic_uef.exe
18_dynamic_rtl_function_table.exe
```

Smoke script запускает analyzer с timeout 8000 ms, trace 32 для handlers и JSON validation.

Targets подтверждают ожидаемые counters:

- VEH registration/hit;
- VCH registration/hit;
- UEF set/hit и exception flow;
- dynamic function table calls.

На macOS эти tests не могут проверить реальный Debug API branch. Нужен Windows CI или физический Windows x64 host.

## Фактическая Windows validation 8 июня 2026 года

Финальная MinGW-w64 сборка dynamic collector была запущена на Windows x64.
Проверенный executable имеет:

```text
SHA-256
489e7571827693cd555c1958f9aec7694d1de717f896d33ecfebe8f13e843624
```

Корпус содержал 18 синтетических и 106 реальных PE-файлов:

```text
124/124 JSON reports прошли schema и semantic validation
86 dynamic sessions были фактически запущены
54 target завершились самостоятельно
32 target корректно остановлены hard timeout
30 DLL/PYD получили ran=false, потому что CreateProcess не запускает library
8 EXE потребовали elevation
4/4 focused VEH/VCH/UEF/runtime-table scenarios прошли
0 dynamic events потеряно
maximum trace_count = 32 при trace_steps = 32
```

Эта проверка подтверждает не только synthetic smoke, но и устойчивость
collector contract на разнообразных реальных EXE: normal exit, nonzero target
exit, GUI/long-running timeout и launch failure. DLL/PYD всё равно не были
исполнены: для них требуется отдельный host process.

Артефакты сохранены в
`reports/dynamic_validation_2026-06-08/`. Скрипт
`tests/validate_dynamic_corpus_evidence.py` повторно проверяет 124
индивидуальных reports, aggregate JSON/CSV, trace budget, dropped events,
source hashes и четыре expected-signal scenarios без повторного запуска
target.

Эмпирическая граница результата: подтверждена MinGW-w64 сборка. MSVC остаётся
отдельным compiler gate и должен проходить в Windows CI на финальной revision.

## Что сделано правильно

Сильные стороны implementation:

- exact separation Windows/non-Windows;
- forwarded API resolution через real module offset;
- bounded event and trace storage;
- command-line quoting;
- instruction cache flush;
- temporary protection restoration;
- per-thread pending re-arm;
- preservation ordinary exception dispatch;
- repeated API breakpoint setup after DLL load;
- partial report retention on failure;
- timeout and cleanup;
- self-check breakpoint bytes.

## Что остаётся улучшить

Наиболее значимые improvements:

1. Remote parse dynamic function tables.
2. Наблюдать removal API и lifetime tables.
3. Typed event schema вместо generic args.
4. Сохранять exception parameters и context snapshots.
5. Поддержать concurrent per-thread traces.
6. Track module unload and invalidate breakpoints.
7. Dynamic capacity или truncation flags для module, breakpoint и pending lists.
8. Return breakpoints для registration API success.
9. Unicode command-line path через `CreateProcessW`.
10. Isolated worker protocol и VM orchestration.
11. Runtime memory protection map.
12. Hardware-breakpoint backend для anti-tamper-sensitive cases.
13. Завершить независимый MSVC gate и расширять Windows version matrix.

## Итоговая state machine

Collector можно представить как finite state machine:

```text
UNINITIALIZED
-> REPORT_INITIALIZED
-> COMMAND_BUILT
-> PROCESS_CREATED
-> WAITING_EVENT
-> HANDLING_EVENT
-> CONTINUING_EVENT
-> WAITING_EVENT
-> EXITED | TIMED_OUT | FAILED
-> BREAKPOINT_CLEANUP
-> HANDLE_CLEANUP
-> REPORT_READY
```

Внутри breakpoint branch существует вложенная state machine:

```text
ARMED
-> HIT
-> ORIGINAL_RESTORED
-> RIP_REWOUND_AND_TF_SET
-> ORIGINAL_INSTRUCTION_EXECUTED
-> SINGLE_STEP
-> REARMED
```

Понимание этих состояний необходимо, чтобы объяснить dynamic part проекта. Она не «просто запускает EXE». Она реализует специализированный user-mode debugger и строит ограниченный, воспроизводимый набор runtime evidence.
