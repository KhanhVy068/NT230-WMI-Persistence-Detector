# Bàn giao TV3 — Detection Engine

TV3 nhận **một bundle** do `collector.normalizer.normalize_data()` trả về. API và CLI chỉ phân tích văn bản cấu hình; chúng không chạy command, giải mã `-EncodedCommand`, mở `script_file_name`, hay truy cập filesystem của máy đã thu thập.

## Gọi từ TV4

```python
from collector.normalizer import normalize_data
from detector.engine import analyze_normalized

normalized_bundle = normalize_data(wmi_data=raw_wmi_data)
report = analyze_normalized(normalized_bundle)

for analysis in report["analyses"]:
    print(analysis["subscription_id"], analysis["matched_rule_ids"])
```

Input phải có các trường top-level `format_version`, `normalization_status`, `subscriptions`, `issues`, và `counts` như Normalizer trả về. Mỗi phần tử `subscriptions` theo [subscription.schema.json](../schemas/subscription.schema.json). TV3 không nhận raw collector JSON trực tiếp.

`analyses` **luôn là danh sách**, một phần tử trên mỗi subscription đầu vào, kể cả khi thiếu dữ liệu. Từ `analysis` số ít trong ví dụ Mốc 4 chỉ là cách gọi tắt cho `report["analyses"][0]`; không phải một field thực tế.

## Report và Alert

Toàn bộ report theo [detection-report.schema.json](../schemas/detection-report.schema.json); từng phần tử `alerts` theo [alert.schema.json](../schemas/alert.schema.json). Cài validator cho tích hợp/CI bằng:

```powershell
python -X utf8 -m pip install -r requirements.txt
python -X utf8 -m unittest tests.test_schema -v
```

Ví dụ sau tạo và in một report thực tế đầy đủ, bao gồm `rule_scope`, `upstream`, bốn `rule_results`, `analyses`, `alerts` và `summary`:

```python
import json
from collector.normalizer import normalize_data
from detector.engine import analyze_normalized

raw = {
    "subscription_id": "TV3-EXAMPLE-R04",
    "computer": "TV3-LAB",
    "namespace": "root\\subscription",
    "filter": {"name": "ExampleFilter", "query": "SELECT * FROM Win32_ProcessStartTrace"},
    "consumer": {
        "name": "ExampleConsumer",
        "type": "ActiveScriptEventConsumer",
        "scripting_engine": "VBScript",
        "script_text": (
            'Set shell = CreateObject("WScript.Shell")\n'
            'shell.Run "cmd.exe /c echo detector"'
        ),
        "script_file_name": None,
    },
    "binding": {"filter": "ExampleFilter", "consumer": "ExampleConsumer"},
}
print(json.dumps(analyze_normalized(normalize_data(wmi_data=raw)), ensure_ascii=False, indent=2))
```

Các phần TV4 thường cần đọc:

| Field | Ý nghĩa |
|---|---|
| `detector_status` | `ok` hoặc `partial`; không suy ra từ số Alert. |
| `enabled_rule_ids` | Mốc hiện tại là `R01`–`R04`. |
| `upstream` | Trạng thái, issues, counts sao chép từ Normalizer. |
| `analyses[]` | Kết luận đầy đủ cho từng subscription. |
| `analyses[].rule_results` | Kết quả từng rule, evidence, notes, dữ liệu thiếu và dạng ngoài phạm vi. |
| `alerts[]` | Một Alert cho mỗi cặp `(subscription, rule)` có `matched`. |
| `summary` | Số đếm được tính từ `analyses` và `alerts`, không phải kết luận độc lập. |

Evidence luôn giữ `field`, `value`, và `matched_text` gốc. R03 thêm `execution_target`, `execution_role`, `path_groups`. R04 matched bắt buộc có hai evidence: `evidence_role = wscript_shell_creation` và `wscript_shell_call`; evidence gọi có `variable`, `method`, `execution_target`, `shell_name`, `command_literal`.

## Trạng thái rule và dữ liệu chưa đủ

| Status | Diễn giải cho TV4 |
|---|---|
| `matched` | Đủ bằng chứng thuộc phạm vi rule; có Alert tương ứng. |
| `not_matched` | Đã phân tích một dạng hỗ trợ và không thỏa điều kiện rule. |
| `not_applicable` | Consumer/dạng lệnh không thuộc phạm vi rule, hoặc là dạng chưa hỗ trợ không thể kết luận an toàn. |
| `insufficient_data` | Thiếu, null, sai kiểu hoặc không tách được dữ liệu cần thiết; xem `unavailable_fields`. |

`detector_status = partial` khi `upstream.normalization_status = partial` hoặc ít nhất một analysis có `data_status = incomplete`. Vẫn hiển thị Alert trong report partial, đồng thời hiển thị `upstream.issues`, `analysis.unavailable_fields`, và `unanalysed_forms` để người dùng không hiểu nhầm phạm vi đã được phân tích hết.

`unanalysed_forms` không phải Alert: đó là danh sách các trường/cú pháp TV3 cố ý không suy đoán. Mỗi entry ở cấp analysis có `field`, `rule_id`, `reason`; entry trong `rule_results[rule_id]` có `field`, `reason`. TV4 nên trình bày riêng các entry này, không cộng vào matched hoặc not_matched.

## Phạm vi rule hiện tại

- **R01:** gọi PowerShell trực tiếp với `-EncodedCommand` đầy đủ, trước `-Command`, `-File` hoặc `--%`.
- **R02:** gọi PowerShell trực tiếp với `-WindowStyle Hidden` đầy đủ, trước `-Command`, `-File` hoặc `--%`.
- **R03:** đích thực thi tĩnh trong Temp, AppData, Downloads hoặc Users\\Public từ executable trực tiếp, PowerShell `-File`, `cmd /c`, `cscript`/`wscript`, hoặc `script_file_name` như nêu trong `rule_scope.R03`; không xác minh file tồn tại, quyền hoặc lần chạy thật.
- **R04:** ActiveScriptEventConsumer VBScript gán `CreateObject("WScript.Shell")` vào biến, rồi chính biến đó gọi `.Run`/`.Exec` với lệnh tĩnh bắt đầu bằng `cmd`, `powershell` hoặc `pwsh` (có/không `.exe`).

Các wrapper, command/script động, chuỗi ghép, script file không có nội dung, JScript, hay nhiều câu lệnh VBScript trên một dòng bằng `:` không được coi là match. Đọc `rule_scope` và `unanalysed_forms` trong report thay vì tự giả định khả năng parser.

## Đếm khi đánh giá

`alerts` đếm theo rule, nên một subscription khớp R01 và R02 có hai Alert. Khi đánh giá ở mức subscription, dự đoán dương là:

```python
predicted_subscription_ids = {
    analysis["subscription_id"]
    for analysis in report["analyses"]
    if analysis["matched_rule_ids"]
}
```

Do đó dùng `summary.subscriptions_with_alerts` hoặc số subscription có `matched_rule_ids` không rỗng cho precision/recall mức subscription; không dùng `summary.alerts`. Khi có cùng `subscription_id` trên host/namespace khác, dùng bộ ba `(computer, namespace, subscription_id)` để định danh.

## CLI và mã thoát

```powershell
python -X utf8 -m detector.engine --input output/normalized.json --output output/detection-report.json
```

| Mã | Ý nghĩa |
|---|---|
| `0` | Report ghi thành công và không có dữ liệu partial; có Alert vẫn là `0`. |
| `1` | Lỗi input JSON/cấu trúc bundle/I/O; output cũ không bị ghi đè. |
| `2` | Đã ghi report nhưng upstream hoặc ít nhất một analysis thiếu dữ liệu. |

CLI không cho `--input` trùng `--output` và ghi output theo cách atomic. Trước khi tích hợp VM hoặc chạy evaluation, TV4 nên dừng/đánh dấu riêng report có mã `2`, sau đó xử lý `issues`, `unavailable_fields`, và `unanalysed_forms` theo ngữ cảnh vận hành.
