# Học TV3 từ code hiện tại

Tài liệu này giải thích Detection Engine theo từng bài ngắn. Ví dụ xuyên suốt là một WMI Subscription giả định tên **MorningCheck**. Consumer của nó có thể gọi PowerShell hoặc chạy VBScript. TV3 chỉ đọc cấu hình đã được Normalizer chuẩn hóa; TV3 không chạy command hay script.

## Bài 1 — Luồng đồ án và nhiệm vụ TV3

**Mục tiêu:** biết dữ liệu đi từ Collector đến Alert như thế nào.

Trước hết, một **Subscription** là liên kết giữa Filter (điều kiện kích hoạt) và Consumer (hành động). Ví dụ MorningCheck có Filter kích hoạt khi `notepad.exe` xuất hiện; Consumer mới là phần TV3 phân tích.

```text
Collector -> Normalizer -> TV3 Detector -> report.analyses + report.alerts -> TV4
                 dữ liệu chuẩn       kết luận theo rule                 hiển thị/tích hợp
```

Normalizer tạo bundle có `subscriptions`. TV3 nhận bundle đó trong `analyze_normalized()`, tạo đúng một `analysis` cho mỗi Subscription, sau đó chỉ tạo Alert khi một rule `matched`.

| Khái niệm | Nghĩa đơn giản |
|---|---|
| Rule | Một điều kiện cảnh báo, ví dụ “PowerShell có `-EncodedCommand`”. |
| Analysis | Toàn bộ kết luận R01–R04 cho một Subscription. |
| Alert | Bản ghi cảnh báo cho một rule đã khớp. Một Analysis có thể sinh nhiều Alert. |
| Evidence | Phần văn bản gốc giải thích vì sao rule khớp. |

**Code nên đọc:** `collector/normalizer.py::normalize_data`, `detector/engine.py::analyze_normalized`, `detector/alert_generator.py::generate_alert`.

### Quiz bài 1

1. TV3 nhận raw JSON trực tiếp từ WMI Collector hay bundle Normalizer?
2. MorningCheck khớp R01 và R02. Có bao nhiêu Analysis và bao nhiêu Alert?
3. Nếu không có Alert, có chắc dữ liệu Collector đầy đủ không?

## Bài 2 — Đọc command line, R01 và R02

**Mục tiêu:** hiểu vì sao phải xác định chương trình được gọi trước khi tìm tham số.

Một **command line** là chuỗi bắt đầu bằng chương trình rồi đến tham số. R01/R02 trước hết tách token và kiểm tra executable trực tiếp có phải `powershell.exe`, `powershell`, `pwsh.exe` hoặc `pwsh` không. Vì vậy chuỗi `cmd.exe /c echo powershell.exe -EncodedCommand ...` không khớp R01: PowerShell chỉ được nhắc đến, không phải chương trình trực tiếp.

Ví dụ MorningCheck:

```text
powershell.exe -EncodedCommand VwByAGkAdABlAA== -WindowStyle Hidden
```

R01 khớp `-EncodedCommand` có giá trị; R02 khớp cặp `-WindowStyle Hidden`. TV3 giữ nguyên `matched_text` và không giải mã hoặc chạy nội dung Base64.

`-Command`, `-File`, và `--%` là **ranh giới**: phần sau chúng là payload/script argument, không còn được đọc như tham số cấp cao R01/R02. Điều này tránh báo nhầm khi payload chỉ in chữ `-WindowStyle Hidden`.

| Rule | Điều kiện trong phạm vi hiện tại |
|---|---|
| R01 | PowerShell trực tiếp + `-EncodedCommand` đầy đủ trước ranh giới. |
| R02 | PowerShell trực tiếp + `-WindowStyle Hidden` trước ranh giới. |

**Code nên đọc:** `detector/rules.py::_tokenize_command_line`, `_direct_powershell_context`, `evaluate_r01`, `evaluate_r02`.

### Quiz bài 2

1. Vì sao `Write-Output '-EncodedCommand abc'` sau `-Command` không khớp R01?
2. Với ví dụ MorningCheck, `matched_rule_ids` chứa những ID nào?
3. Áp dụng: `cmd.exe /c powershell.exe -WindowStyle Hidden` có khớp R02 trong scope hiện tại không? Vì sao?

## Bài 3 — Đích thực thi và R03

**Mục tiêu:** phân biệt file thật sự được cấu hình để chạy với đường dẫn chỉ là dữ liệu.

R03 không hỏi “chuỗi có chữ Temp không?”. Nó tìm **đích thực thi tĩnh** trong một ngữ cảnh được hỗ trợ. Đích có thể là executable trực tiếp, `ExecutablePath`, script sau PowerShell `-File`, file sau `cmd /c`, script truyền cho `cscript`/`wscript`, hoặc `script_file_name` của ActiveScript Consumer.

Ví dụ MorningCheck đổi thành:

```text
cscript.exe //NoLogo "C:\Users\Lab\Downloads\check.vbs"
```

`cscript.exe` là script host; `//NoLogo` là option nên bị bỏ qua; `check.vbs` là script tĩnh được thực thi. Vì nằm trong Downloads, R03 khớp với `execution_role = script_host_file` và `path_groups = ["Downloads"]`.

TV3 hiểu đường dẫn theo ngữ nghĩa Windows, kể cả `%TEMP%`, `%APPDATA%`, `%PUBLIC%`, `%USERPROFILE%\Downloads`. TV3 không kiểm tra file tồn tại, quyền ghi hay có thực sự chạy.

| Có thể kết luận | Không thể kết luận |
|---|---|
| Cấu hình chỉ đến path thuộc nhóm lab. | File có tồn tại, ghi được, hoặc đã chạy. |
| Đường dẫn là đích trong một dạng lệnh hỗ trợ. | Path chỉ được đọc/in trong payload động. |

**Code nên đọc:** `detector/rules.py::_classify_static_windows_path`, `_add_execution_target`, `_extract_r03_targets`, `evaluate_r03`.

### Quiz bài 3

1. `C:\TempTools\run.exe` có thuộc nhóm Temp R03 không?
2. Vì sao `powershell.exe -Command "Get-Content C:\Temp\x.txt"` không là R03 match?
3. Áp dụng: file `.vbs` nào là evidence trong ví dụ MorningCheck mới và role của nó là gì?

## Bài 4 — Quan hệ biến VBScript và R04

**Mục tiêu:** hiểu R04 cần chứng minh mối liên hệ, không chỉ tìm từ khóa.

R04 áp dụng cho `ActiveScriptEventConsumer` có `scripting_engine = VBScript` và `script_text`. Nó theo dõi biến được gán `CreateObject("WScript.Shell")`, rồi đòi chính biến đó gọi `.Run` hoặc `.Exec` với command literal tĩnh bắt đầu bằng shell hỗ trợ (`cmd`, `powershell`, `pwsh`).

```vbscript
Set shell = CreateObject("WScript.Shell")
shell.Run "cmd.exe /c echo MorningCheck"
```

Hai dòng trên tạo hai evidence R04: một evidence `wscript_shell_creation`, một evidence `wscript_shell_call`. Nếu `shell` bị gán `Nothing` trước `.Run`, hoặc `other.Run ...` là đối tượng khác, R04 không khớp.

Comment và chuỗi dữ liệu cũng khác code. Chuỗi `message = "WScript.Shell cmd.exe"` không tạo đối tượng. Cú pháp động, nhiều lệnh dùng `:` trên một dòng, line continuation, JScript, hay chỉ có `script_file_name` được ghi vào `unanalysed_forms`/`insufficient_data`, không bị suy đoán là match.

**Code nên đọc:** `detector/rules.py::_vbscript_code`, `_parse_vbscript_r04`, `evaluate_r04`.

### Quiz bài 4

1. Vì sao chỉ có `CreateObject("WScript.Shell")` chưa đủ cho R04?
2. Một script dùng `other.Run "cmd.exe"` sau khi tạo biến `shell` có khớp không?
3. Áp dụng: nếu `script_text` là `null` nhưng có `script_file_name`, R04 trả trạng thái gì và vì sao?

## Bài 5 — Analysis, Alert, schema, API và CLI

**Mục tiêu:** biết cách dùng output an toàn trong TV4.

`analysis` có `matched_rule_ids`, `rule_results`, `unavailable_fields`, `unanalysed_forms`, `data_status`. `alert` có `alert_id` ổn định theo computer, namespace, subscription ID và rule ID. Vì thế hai máy có cùng subscription ID vẫn không gộp nhầm Alert.

```python
from detector.engine import analyze_normalized

report = analyze_normalized(normalized_bundle)
for analysis in report["analyses"]:
    if analysis["data_status"] == "incomplete":
        print(analysis["unavailable_fields"])
```

Hai schema quan trọng là `schemas/detection-report.schema.json` và `schemas/alert.schema.json`. Alert R04 phải có evidence tạo đối tượng lẫn evidence gọi shell. `tests/test_schema.py` dùng `jsonschema`, không tự viết validator JSON Schema.

CLI dùng:

```powershell
python -X utf8 -m detector.engine --input output/normalized.json --output output/detection-report.json
```

| Exit code | Nghĩa |
|---|---|
| 0 | Report hoàn tất, kể cả có Alert. |
| 1 | Lỗi input/cấu trúc/I/O, không ghi đè input. |
| 2 | Đã có report nhưng dữ liệu upstream hoặc analysis partial. |

**Code nên đọc:** `detector/engine.py::analyze_subscription`, `_summary`, `analyze_normalized`; `detector/alert_generator.py`; `schemas/`.

### Quiz bài 5

1. Alert có được tạo khi rule là `not_matched` không?
2. TV4 nên hiển thị field nào khi `data_status = incomplete`?
3. Áp dụng: MorningCheck khớp R01 và R02. `summary.alerts` và `summary.subscriptions_with_alerts` tăng bao nhiêu?

## Bài 6 — Test và evaluation

**Mục tiêu:** hiểu cách tin vào thay đổi mà không dùng evaluation để học rule.

Development chỉ phục vụ xây và sửa rule. Khi code đã được commit/hash, `tools/evaluate_detector.py` mới đọc labels evaluation để tạo kết quả tái hiện được trong `results/`. Script phân biệt metric Subscription với metric Rule và giữ `incomplete`/`unanalysed_forms` trong coverage.

```text
Sửa rule -> regression development -> commit + hash baseline
        -> evaluation -> ghi kết quả -> nếu phát hiện lỗi, giữ kết quả cũ
        -> sửa có test -> baseline mới -> evaluation chạy lại riêng
```

Đây là lý do repository có hai file kết quả: baseline đầu phát hiện S006 thiếu support `cscript`; baseline sau thêm support và không xóa lịch sử đầu.

| Lệnh | Mục đích |
|---|---|
| `python -X utf8 -m unittest discover -s tests -p test_detector.py -v` | Regression rule/API/CLI. |
| `python -X utf8 -m unittest tests.test_schema -v` | Schema và report contract. |
| `python -X utf8 tests/run_collector_tests.py --temp-dir <empty-dir>` | Collector test khi Python Store không ghi `%TEMP%`. |
| `python -X utf8 tools/evaluate_detector.py --baseline <sha> --output <file>` | Evaluation tách khỏi Detector. |

**Code nên đọc:** `tests/test_detector.py`, `tests/test_schema.py`, `tests/test_evaluate_detector.py`, `tools/evaluate_detector.py`, `docs/tv3_evaluation.md`.

### Quiz bài 6

1. Vì sao một Subscription khớp hai rule vẫn chỉ là một positive ở metric Subscription?
2. Khi Precision không có mẫu số, script ghi giá trị nào và tại sao?
3. Áp dụng: phát hiện FN mới sau evaluation thì cần giữ lại những gì trước khi chạy lại?

# Đáp án và giải thích

## Bài 1

1. Bundle Normalizer; Detector kiểm tra các field hợp đồng đã chuẩn hóa.
2. Một Analysis, hai Alert: mỗi rule matched sinh một Alert.
3. Không. Có thể report partial hoặc rule nằm ngoài scope; xem `detector_status`, `data_status`, issues và forms chưa phân tích.

## Bài 2

1. Sau `-Command` đó là payload, không phải option PowerShell cấp cao mà R01 được phép đọc.
2. `R01` và `R02`.
3. Không. Executable trực tiếp là `cmd.exe`; wrapper gián tiếp nằm ngoài scope hiện tại.

## Bài 3

1. Không; `TempTools` không phải component thư mục `Temp` chính xác.
2. Path là dữ liệu của script `-Command`, không phải đích thực thi tĩnh R03 được hỗ trợ.
3. `C:\Users\Lab\Downloads\check.vbs`, role `script_host_file`.

## Bài 4

1. Chưa có hành động khởi chạy shell; R04 cần cả tạo đối tượng và gọi đúng biến.
2. Không. R04 không nối `other` với `WScript.Shell` đã gán cho `shell`.
3. `insufficient_data`: không có nội dung script để phân tích và TV3 không mở file từ máy chạy Detector.

## Bài 5

1. Không, chỉ `matched` tạo Alert.
2. `unavailable_fields`, `unanalysed_forms` và upstream issues nếu có.
3. `alerts` tăng 2, còn `subscriptions_with_alerts` tăng 1.

## Bài 6

1. Vì metric đó trả lời “Subscription có cần cảnh báo không?”, không đếm số lý do cảnh báo.
2. `null`, để không gán ý nghĩa sai cho 0 hoặc 1 khi không có mẫu số.
3. Giữ file evaluation và baseline/hash cũ, ghi rõ phát hiện, thêm test/fix, rồi tạo baseline và file evaluation mới.
